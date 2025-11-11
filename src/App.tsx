import React, { useState } from "react";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import {
  IconGlobe,
  IconNetwork,
} from "@tabler/icons-react";
import { motion } from "motion/react";
import { cn } from "@/lib/utils";
import { PacketCapture } from "@/components/PacketCapture/PacketCapture";
import { HTTPProxy } from "@/components/HTTPProxy/HTTPProxy";
import { TitleBar } from "@/components/TitleBar/TitleBar";

export default function App() {
  const links = [
    {
      label: "Packet Capture",
      href: "#capture",
      icon: (
        <IconNetwork className="h-5 w-5 shrink-0 text-neutral-700 dark:text-neutral-200" />
      ),
    },
    {
      label: "HTTP Proxy",
      href: "#proxy",
      icon: (
        <IconGlobe className="h-5 w-5 shrink-0 text-neutral-700 dark:text-neutral-200" />
      ),
    },
  ];
  const [open, setOpen] = useState(false);
  const [activeView, setActiveView] = useState<"capture" | "proxy">("capture");

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-white dark:bg-neutral-900">
      <TitleBar />
      <div
        className={cn(
          "mx-auto flex w-full flex-1 flex-row overflow-hidden bg-white dark:bg-neutral-900"
        )}
      >
        <Sidebar open={open} setOpen={setOpen}>
        <SidebarBody className="justify-between gap-10">
          <div className="flex flex-1 flex-col overflow-x-hidden overflow-y-auto">
            {open ? <Logo /> : <LogoIcon />}
            <div className="mt-8 flex flex-col gap-2">
              {links.map((link, idx) => (
                <div
                  key={idx}
                  onClick={() => {
                    const view = link.href.replace("#", "") as "capture" | "proxy";
                    setActiveView(view);
                  }}
                >
                  <SidebarLink link={link} />
                </div>
              ))}
            </div>
          </div>
        </SidebarBody>
        </Sidebar>
        <Dashboard activeView={activeView} />
      </div>
    </div>
  );
}

export const Logo = () => {
  return (
    <a
      href="#"
      className="relative z-20 flex items-center space-x-2 py-1 text-sm font-normal text-black"
    >
      <div className="h-5 w-6 shrink-0 rounded-tl-lg rounded-tr-sm rounded-br-lg rounded-bl-sm bg-purple-600 dark:bg-purple-500" />
      <motion.span
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="font-medium whitespace-pre text-black dark:text-white"
      >
        Network Monitor
      </motion.span>
    </a>
  );
};

export const LogoIcon = () => {
  return (
    <a
      href="#"
      className="relative z-20 flex items-center space-x-2 py-1 text-sm font-normal text-black"
    >
      <div className="h-5 w-6 shrink-0 rounded-tl-lg rounded-tr-sm rounded-br-lg rounded-bl-sm bg-purple-600 dark:bg-purple-500" />
    </a>
  );
};

// Dashboard component with packet capture and proxy views
const Dashboard = ({ activeView }: { activeView: "capture" | "proxy" }) => {
  return (
    <div className="flex flex-1 overflow-hidden">
      <div className="flex h-full w-full flex-1 flex-col rounded-tl-2xl border border-neutral-200 bg-white p-4 md:p-6 dark:border-neutral-700 dark:bg-neutral-900 overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-bold text-neutral-800 dark:text-neutral-200">
            {activeView === "capture" ? "Packet Capture" : "HTTP Proxy"}
          </h1>
        </div>

        <div className="flex-1 min-h-0">
          {activeView === "capture" ? (
            <PacketCapture />
          ) : (
            <HTTPProxy />
          )}
        </div>
      </div>
    </div>
  );
};
