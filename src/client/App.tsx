import DevicesPage from './pages/DevicesPage'
import './App.css'

export default function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Clawdbot Admin</h1>
      </header>
      <main className="app-main">
        <DevicesPage />
      </main>
    </div>
  )
}
