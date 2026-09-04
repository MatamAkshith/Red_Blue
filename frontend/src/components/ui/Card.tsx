import React from "react";

interface CardProps {
  children: React.ReactNode;
  className?: string;
  title?: React.ReactNode;
  subtitle?: string;
  action?: React.ReactNode;
  headerBorder?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  className = "",
  title,
  subtitle,
  action,
  headerBorder = true,
}) => {
  return (
    <div
      className={`bg-white border border-slate-200 rounded-sm shadow-2xs ${className}`}
    >
      {(title || action) && (
        <div
          className={`px-4 py-3 flex items-center justify-between ${
            headerBorder ? "border-b border-slate-200/80" : ""
          }`}
        >
          <div>
            {typeof title === "string" ? (
              <h3 className="text-sm font-semibold text-slate-900 tracking-tight">
                {title}
              </h3>
            ) : (
              title
            )}
            {subtitle && (
              <p className="text-xs text-slate-500 font-normal mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
          {action && <div className="flex items-center space-x-2">{action}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
};
