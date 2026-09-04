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
    <div className="flex h-screen w-screen overflow-hidden bg-slate-50 text-slate-900">
      {/* Sidebar Left */}
      <aside className="w-60 shrink-0 border-r border-slate-200 bg-white flex flex-col justify-between">
        <div>
          {/* Brand Logo Header */}
          <div className="h-14 px-4 flex items-center space-x-3 border-b border-slate-200">
            <div className="w-7 h-7 rounded-xs bg-slate-900 text-white flex items-center justify-center font-mono font-bold text-xs shadow-2xs">
              BB
            </div>
            <div>
              <div className="text-xs font-bold tracking-tight text-slate-900 uppercase font-mono">
                BLACKBOX
              </div>
              <div className="text-[10px] font-mono text-slate-500 tracking-wider">
                SOC ENGINE v1.4
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-6 overflow-y-auto">
            {navGroupings.map((group) => (
              <div key={group.group}>
                <div className="px-2 mb-1.5 text-[10px] font-mono font-bold tracking-widest text-slate-400 uppercase">
                  {group.group}
                </div>
                <div className="space-y-0.5">
                  {group.items.map((item) => {
                    const isActive = activeItem === item.name;
                    return (
                      <button
                        key={item.name}
                        onClick={() => handleNavClick(item.name)}
                        className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-xs text-xs font-medium transition-colors cursor-pointer ${
                          isActive
                            ? "bg-blue-50 text-blue-700 font-semibold border-r-2 border-blue-600"
                            : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                        }`}
                      >
                        <div className="flex items-center space-x-2">
                          <span className="text-xs">{item.icon}</span>
                          <span>{item.name}</span>
                        </div>
                        {item.count !== undefined && (
                          <span
                            className={`px-1.5 py-0.2 rounded-full font-mono text-[10px] ${
                              isActive
                                ? "bg-blue-600 text-white"
                                : "bg-slate-200 text-slate-700"
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
        <div className="p-3 border-t border-slate-200 bg-slate-50/50">
          <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>DETECTOR</span>
            <span className="text-emerald-600 font-medium">ONLINE</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-500 font-mono mt-1">
            <span>FEATHERLESS</span>
            <span className="text-emerald-600 font-medium">CONNECTED</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
        {/* Topbar Header */}
        <header className="h-14 shrink-0 bg-white border-b border-slate-200 px-6 flex items-center justify-between z-10 shadow-2xs">
          <div className="flex items-center space-x-4">
            <h1 className="text-sm font-bold text-slate-900 uppercase tracking-tight font-mono">
              BLACKBOX Security Operations
            </h1>
            <span className="h-4 w-px bg-slate-200" />
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span className="text-emerald-700 font-semibold uppercase tracking-wider text-[11px]">
                ● LIVE MONITORING
              </span>
            </div>
          </div>

          {/* Topbar Right Controls */}
          <div className="flex items-center space-x-4">
            <div className="text-xs font-mono text-slate-500 bg-slate-100 px-2.5 py-1 rounded-xs border border-slate-200">
              CLUSTER: <span className="text-slate-900 font-semibold">US-EAST-SOC</span>
            </div>
            <div className="text-xs font-mono text-slate-500">
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

