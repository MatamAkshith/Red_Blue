import { SecurityDashboardLayout } from "./components/layout/SecurityDashboardLayout";
import { IncidentView } from "./pages/IncidentView";

function App() {
  return (
    <SecurityDashboardLayout activeNavItem="Incidents">
      <IncidentView />
    </SecurityDashboardLayout>
  );
}

export default App;
