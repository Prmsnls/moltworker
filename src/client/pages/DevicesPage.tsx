import { useState, useEffect, useCallback } from 'react'
import {
  listDevices,
  approveDevice,
  approveAllDevices,
  restartGateway,
  AuthError,
  type PendingDevice,
  type PairedDevice,
  type DeviceListResponse,
} from '../api'
import './DevicesPage.css'

export default function DevicesPage() {
  const [pending, setPending] = useState<PendingDevice[]>([])
  const [paired, setPaired] = useState<PairedDevice[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)
  const [restartInProgress, setRestartInProgress] = useState(false)

  const fetchDevices = useCallback(async () => {
    try {
      setError(null)
      const data: DeviceListResponse = await listDevices()
      setPending(data.pending || [])
      setPaired(data.paired || [])
      
      if (data.error) {
        setError(data.error)
      } else if (data.parseError) {
        setError(`Parse error: ${data.parseError}`)
      }
    } catch (err) {
      if (err instanceof AuthError) {
        setError('Authentication required. Please log in via Cloudflare Access.')
      } else {
        setError(err instanceof Error ? err.message : 'Failed to fetch devices')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDevices()
    // Poll every 10 seconds for new pairing requests
    const interval = setInterval(fetchDevices, 10000)
    return () => clearInterval(interval)
  }, [fetchDevices])

  const handleApprove = async (requestId: string) => {
    setActionInProgress(requestId)
    try {
      const result = await approveDevice(requestId)
      if (result.success) {
        // Refresh the list
        await fetchDevices()
      } else {
        setError(result.error || 'Approval failed')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to approve device')
    } finally {
      setActionInProgress(null)
    }
  }

  const handleApproveAll = async () => {
    if (pending.length === 0) return
    
    setActionInProgress('all')
    try {
      const result = await approveAllDevices()
      if (result.failed && result.failed.length > 0) {
        setError(`Failed to approve ${result.failed.length} device(s)`)
      }
      // Refresh the list
      await fetchDevices()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to approve devices')
    } finally {
      setActionInProgress(null)
    }
  }

  const handleRestartGateway = async () => {
    if (!confirm('Are you sure you want to restart the gateway? This will disconnect all clients temporarily.')) {
      return
    }
    
    setRestartInProgress(true)
    try {
      const result = await restartGateway()
      if (result.success) {
        setError(null)
        // Show success message briefly
        alert('Gateway restart initiated. Clients will reconnect automatically.')
      } else {
        setError(result.error || 'Failed to restart gateway')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restart gateway')
    } finally {
      setRestartInProgress(false)
    }
  }

  const formatTimestamp = (ts: number) => {
    const date = new Date(ts)
    return date.toLocaleString()
  }

  const formatTimeAgo = (ts: number) => {
    const seconds = Math.floor((Date.now() - ts) / 1000)
    if (seconds < 60) return `${seconds}s ago`
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    return `${days}d ago`
  }

  return (
    <div className="devices-page">
      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="dismiss-btn">
            Dismiss
          </button>
        </div>
      )}

      <section className="devices-section gateway-section">
        <div className="section-header">
          <h2>Gateway Controls</h2>
          <button
            className="btn btn-danger"
            onClick={handleRestartGateway}
            disabled={restartInProgress}
          >
            {restartInProgress ? 'Restarting...' : 'Restart Gateway'}
          </button>
        </div>
        <p className="hint">
          Restart the gateway to apply configuration changes or recover from errors.
          All connected clients will be temporarily disconnected.
        </p>
      </section>

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading devices...</p>
        </div>
      ) : (
        <>
          <section className="devices-section">
        <div className="section-header">
          <h2>Pending Pairing Requests</h2>
          {pending.length > 0 && (
            <button
              className="btn btn-primary"
              onClick={handleApproveAll}
              disabled={actionInProgress !== null}
            >
              {actionInProgress === 'all' ? 'Approving...' : `Approve All (${pending.length})`}
            </button>
          )}
        </div>

        {pending.length === 0 ? (
          <div className="empty-state">
            <p>No pending pairing requests</p>
            <p className="hint">
              Devices will appear here when they attempt to connect without being paired.
            </p>
          </div>
        ) : (
          <div className="devices-grid">
            {pending.map((device) => (
              <div key={device.requestId} className="device-card pending">
                <div className="device-header">
                  <span className="device-name">
                    {device.displayName || device.deviceId || 'Unknown Device'}
                  </span>
                  <span className="device-badge pending">Pending</span>
                </div>
                <div className="device-details">
                  {device.platform && (
                    <div className="detail-row">
                      <span className="label">Platform:</span>
                      <span className="value">{device.platform}</span>
                    </div>
                  )}
                  {device.clientId && (
                    <div className="detail-row">
                      <span className="label">Client:</span>
                      <span className="value">{device.clientId}</span>
                    </div>
                  )}
                  {device.clientMode && (
                    <div className="detail-row">
                      <span className="label">Mode:</span>
                      <span className="value">{device.clientMode}</span>
                    </div>
                  )}
                  {device.role && (
                    <div className="detail-row">
                      <span className="label">Role:</span>
                      <span className="value">{device.role}</span>
                    </div>
                  )}
                  {device.remoteIp && (
                    <div className="detail-row">
                      <span className="label">IP:</span>
                      <span className="value">{device.remoteIp}</span>
                    </div>
                  )}
                  <div className="detail-row">
                    <span className="label">Requested:</span>
                    <span className="value" title={formatTimestamp(device.ts)}>
                      {formatTimeAgo(device.ts)}
                    </span>
                  </div>
                </div>
                <div className="device-actions">
                  <button
                    className="btn btn-success"
                    onClick={() => handleApprove(device.requestId)}
                    disabled={actionInProgress !== null}
                  >
                    {actionInProgress === device.requestId ? 'Approving...' : 'Approve'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="devices-section">
        <div className="section-header">
          <h2>Paired Devices</h2>
          <button className="btn btn-secondary" onClick={fetchDevices}>
            Refresh
          </button>
        </div>

        {paired.length === 0 ? (
          <div className="empty-state">
            <p>No paired devices</p>
          </div>
        ) : (
          <div className="devices-grid">
            {paired.map((device, index) => (
              <div key={device.deviceId || index} className="device-card paired">
                <div className="device-header">
                  <span className="device-name">
                    {device.displayName || device.deviceId || 'Unknown Device'}
                  </span>
                  <span className="device-badge paired">Paired</span>
                </div>
                <div className="device-details">
                  {device.platform && (
                    <div className="detail-row">
                      <span className="label">Platform:</span>
                      <span className="value">{device.platform}</span>
                    </div>
                  )}
                  {device.clientId && (
                    <div className="detail-row">
                      <span className="label">Client:</span>
                      <span className="value">{device.clientId}</span>
                    </div>
                  )}
                  {device.clientMode && (
                    <div className="detail-row">
                      <span className="label">Mode:</span>
                      <span className="value">{device.clientMode}</span>
                    </div>
                  )}
                  {device.role && (
                    <div className="detail-row">
                      <span className="label">Role:</span>
                      <span className="value">{device.role}</span>
                    </div>
                  )}
                  <div className="detail-row">
                    <span className="label">Paired:</span>
                    <span className="value" title={formatTimestamp(device.approvedAtMs)}>
                      {formatTimeAgo(device.approvedAtMs)}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
        </>
      )}
    </div>
  )
}
