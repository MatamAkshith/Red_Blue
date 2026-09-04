import React from "react";
import type { AgentEvent } from "../../api";
import { Badge, type BadgeVariant } from "../ui/Badge";

interface EventInspectorDrawerProps {
  event: AgentEvent | null;
  onClose: () => void;
}

export const EventInspectorDrawer: React.FC<EventInspectorDrawerProps> = ({
  event,
  onClose,
}) => {
  if (!event) return null;

  const getTrustBadgeVariant = (trust: string): BadgeVariant => {
    switch (trust?.toUpperCase()) {
      case "UNTRUSTED":
        return "suspicious";
      case "TRUSTED":
        return "success";
      default:
        return "neutral";
    }
  };

  const getEventTypeVariant = (type: string): BadgeVariant => {
    switch (type) {
      case "INPUT":
      case "RETRIEVAL":
        return "warning";
      case "DECISION":
      case "TOOL_CALL":
      case "ACTION":
        return "critical";
      default:
        return "neutral";
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-white border-l border-slate-200 shadow-xl z-50 flex flex-col justify-between overflow-hidden animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div>
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/80">
          <div>
            <div className="text-[10px] font-mono font-bold tracking-widest text-slate-400 uppercase">
              EVENT INSPECTOR / SOC TELEMETRY
            </div>
            <div className="flex items-center space-x-2 mt-1">
              <span className="font-mono font-bold text-base text-slate-900 bg-white px-2 py-0.5 rounded-xs border border-slate-300">
                {event.event_id}
              </span>
              <Badge variant={getEventTypeVariant(event.event_type)}>
                {event.event_type}
              </Badge>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 text-lg font-bold p-1 rounded-xs hover:bg-slate-200 transition-colors cursor-pointer"
            title="Close Inspector"
          >
            ✕
          </button>
        </div>

        {/* Metadata Properties Body */}
        <div className="p-5 space-y-5 overflow-y-auto max-h-[calc(100vh-140px)]">
          {/* Trust Boundary & Identity */}
          <div className="bg-slate-50 p-3 rounded-xs border border-slate-200/80 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500">TRUST BOUNDARY:</span>
              <Badge variant={getTrustBadgeVariant(event.trust_level)}>
                {event.trust_level}
              </Badge>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500">PARENT EVENT ID:</span>
              <span className="font-bold text-slate-800">
                {event.parent_event_id || "NONE (ROOT)"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500">TIMESTAMP (UTC):</span>
              <span className="text-slate-700 font-semibold text-[11px]">
                {event.timestamp
                  ? new Date(event.timestamp).toISOString()
                  : "N/A"}
              </span>
            </div>
          </div>

          {/* Core Fields */}
          <div className="space-y-3 font-mono text-xs">
            <div>
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Source Entity
              </span>
              <span className="font-semibold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-200 inline-block mt-0.5">
                {event.source}
              </span>
            </div>

            <div>
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Target Entity
              </span>
              <span className="font-semibold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-200 inline-block mt-0.5">
                {event.target || "N/A"}
              </span>
            </div>

            <div>
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Resource URI
              </span>
              <span className="font-semibold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-200 inline-block mt-0.5 break-all">
                {event.resource || "N/A"}
              </span>
            </div>

            <div>
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Operation / Action
              </span>
              <span className="font-semibold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-200 inline-block mt-0.5">
                {event.action || "N/A"}
              </span>
            </div>

            <div>
              <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                Declared Permission
              </span>
              <span className="font-semibold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-xs border border-slate-200 inline-block mt-0.5">
                {event.permission || "NONE"}
              </span>
            </div>
          </div>

          {/* Evidence Block */}
          <div className="space-y-1.5">
            <div className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-1">
              <span>🧾 FORENSIC EVIDENCE & METADATA</span>
            </div>
            <div className="bg-slate-900 text-slate-100 p-3 rounded-xs font-mono text-[11px] overflow-x-auto border border-slate-800 leading-relaxed">
              {event.metadata && Object.keys(event.metadata).length > 0 ? (
                <pre className="whitespace-pre-wrap">
                  {JSON.stringify(event.metadata, null, 2)}
                </pre>
              ) : (
                <span className="text-slate-500 italic">
                  No additional metadata payload attached.
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs font-mono">
        <span className="text-slate-500">AGENT ID:</span>
        <span className="font-bold text-slate-800">{event.agent_id}</span>
      </div>
    </div>
  );
};
