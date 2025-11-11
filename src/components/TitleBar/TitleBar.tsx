import React, { useState, useEffect } from 'react';
import { IconMinus, IconMaximize, IconX } from '@tabler/icons-react';
import { cn } from '@/lib/utils';

export const TitleBar: React.FC = () => {
  const [isMaximized, setIsMaximized] = useState(false);

  useEffect(() => {
    const checkMaximized = async () => {
      if (window.api) {
        const maximized = await window.api.windowIsMaximized();
        setIsMaximized(maximized);
      }
    };
    checkMaximized();
  }, []);

  const handleMinimize = async () => {
    if (window.api) {
      await window.api.windowMinimize();
    }
  };

  const handleMaximize = async () => {
    if (window.api) {
      const maximized = await window.api.windowMaximize();
      setIsMaximized(maximized);
    }
  };

  const handleClose = async () => {
    if (window.api) {
      await window.api.windowClose();
    }
  };

  return (
    <div className="flex items-center justify-between bg-neutral-900 text-white h-8 px-3 select-none" style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}>
      <div className="flex items-center gap-2">
        <div className="h-4 w-4 rounded-sm bg-purple-600" />
        <span className="text-xs font-medium">Network Monitor</span>
      </div>

      <div className="flex items-center" style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}>
        <button
          onClick={handleMinimize}
          className="h-8 w-12 flex items-center justify-center hover:bg-neutral-700 transition-colors"
          aria-label="Minimize"
        >
          <IconMinus size={16} />
        </button>
        <button
          onClick={handleMaximize}
          className="h-8 w-12 flex items-center justify-center hover:bg-neutral-700 transition-colors"
          aria-label={isMaximized ? "Restore" : "Maximize"}
        >
          <IconMaximize size={14} />
        </button>
        <button
          onClick={handleClose}
          className="h-8 w-12 flex items-center justify-center hover:bg-red-600 transition-colors"
          aria-label="Close"
        >
          <IconX size={16} />
        </button>
      </div>
    </div>
  );
};
