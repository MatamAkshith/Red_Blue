import React, { useEffect, useState } from "react";

interface SecurityDashboardLayoutProps {
  children: React.ReactNode;
  activeNavItem?: string;
  onNavItemClick?: (item: string) => void;
  incidentsCount?: number;
}

export const SecurityDashboardLayout: React.FC<SecurityDashboardLayoutProps> = ({
  children,
  activeNavItem = "Overview",
  onNavItemClick,
  incidentsCount = 0,
}) => {
  const [activeItem, setActiveItem] = useState(activeNavItem);

  useEffect(() => {
    setActiveItem(activeNavItem);
  }, [activeNavItem]);

  useEffect(() => {
    document.title = "RedBlue Security Operations";
  }, []);

  const handleNavClick = (item: string) => {
    setActiveItem(item);
    if (onNavItemClick) {
      onNavItemClick(item);
    }
  };

  const navGroupings = [
    {
      group: "OPERATIONS",
      items: [
        { name: "Overview", icon: "📊" },
        {
          name: "Incidents",
          icon: "🚨",
          count: incidentsCount > 0 ? incidentsCount : undefined,
        },
      ],
    },
    {
      group: "ANALYSIS",
      items: [
        { name: "Execution", icon: "⚡" },
        { name: "Attack Path", icon: "⛓️" },
      ],
    },
    {
      group: "IMPACT",
      items: [
        { name: "AEGIS", icon: "🛡️" },
        { name: "What-If", icon: "🔮" },
      ],
    },
    {
      group: "RESPONSE",
      items: [
        { name: "Intervention", icon: "⚙️" },
        { name: "CHIMERA", icon: "⚔️" },
        { name: "Verify", icon: "✅" },
      ],
    },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-50 text-slate-900 font-sans">
      {/* Sidebar Left */}
      <aside className="w-64 shrink-0 border-r border-slate-200 bg-white flex flex-col justify-between">
        <div>
          {/* Brand Logo Header */}
          <div className="h-16 px-4 flex items-center space-x-3 border-b border-slate-200">
            <div className="w-8 h-8 rounded-xs bg-slate-900 text-white flex items-center justify-center font-sans font-bold text-xs shadow-2xs">
              <span className="text-blue-500 font-bold">R</span>
              <span className="text-red-500 font-bold">B</span>
            </div>
            <div>
              <div className="text-base font-extrabold tracking-tight uppercase font-sans flex items-center">
                <span className="text-blue-600">RED</span>
                <span className="text-red-600">BLUE</span>
              </div>
              <div className="text-[11px] font-sans text-slate-500 font-semibold tracking-wider">
                SOC ENGINE v1.4
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3.5 space-y-6 overflow-y-auto">
            {navGroupings.map((group) => (
              <div key={group.group}>
                <div className="px-2 mb-2 text-[11px] font-sans font-bold tracking-widest text-slate-400 uppercase">
                  {group.group}
                </div>
                <div className="space-y-1">
                  {group.items.map((item) => {
                    const isActive = activeItem === item.name;
                    return (
                      <button
                        key={item.name}
                        onClick={() => handleNavClick(item.name)}
                        className={`w-full flex items-center justify-between px-3 py-2 rounded-xs text-sm font-medium transition-colors cursor-pointer ${
                          isActive
                            ? "bg-blue-50 text-blue-700 font-bold border-r-2 border-blue-600"
                            : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                        }`}
                      >
                        <div className="flex items-center space-x-2.5">
                          <span className="text-sm">{item.icon}</span>
                          <span>{item.name}</span>
                        </div>
                        {item.count !== undefined && (
                          <span
                            className={`px-2 py-0.5 rounded-full font-mono text-xs ${
                              isActive
                                ? "bg-blue-600 text-white font-bold"
                                : "bg-slate-200 text-slate-700 font-semibold"
                            }`}
                          >
                            {item.count}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
        </div>

        {/* Sidebar Footer System Status */}
        <div className="p-4 border-t border-slate-200 bg-slate-50/60 font-sans">
          <div className="flex items-center justify-between text-xs text-slate-600 font-semibold">
            <span>DETECTOR</span>
            <span className="text-emerald-600 font-bold">ONLINE</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-600 font-semibold mt-1.5">
            <span>FEATHERLESS</span>
            <span className="text-emerald-600 font-bold">CONNECTED</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
        {/* Topbar Header */}
        <header className="h-16 shrink-0 bg-white border-b border-slate-200 px-6 flex items-center justify-between z-10 shadow-2xs">
          <div className="flex items-center space-x-4">
            <h1 className="text-base font-extrabold uppercase tracking-tight font-sans flex items-center space-x-1">
              <span className="text-blue-600">RED</span>
              <span className="text-red-600">BLUE</span>
              <span className="text-slate-900 ml-2 font-bold">Security Operations</span>
            </h1>
            <span className="h-4 w-px bg-slate-200" />
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span className="text-emerald-700 font-bold uppercase tracking-wider text-xs">
                ● LIVE MONITORING
              </span>
            </div>
          </div>

          {/* Topbar Right Controls */}
          <div className="flex items-center space-x-4">
            <div className="text-xs font-mono text-slate-600 bg-slate-100 px-3 py-1 rounded-xs border border-slate-200 font-semibold">
              CLUSTER: <span className="text-slate-900 font-bold">US-EAST-SOC</span>
            </div>
            <div className="text-xs font-mono text-slate-500 font-semibold">
              AGENT TELEMETRY STREAM
            </div>
          </div>
        </header>

        {/* Fluid Scrollable Content Canvas */}
        <main className="flex-1 overflow-y-auto bg-slate-50 p-6">
          <div className="max-w-7xl mx-auto space-y-6">{children}</div>
        </main>
      </div>
    </div>
  );
};

