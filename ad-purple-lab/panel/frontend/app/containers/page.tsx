"use client";

import { useCallback, useEffect, useState } from "react";
import { api, type Container } from "@/lib/api";
import { ContainerTable } from "@/components/soc/ContainerTable";
import { Box } from "lucide-react";

export default function ContainersPage() {
  const [containers, setContainers] = useState<Container[]>([]);
  const [loading,    setLoading]    = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setContainers(await api.containers());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 20_000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Box className="w-6 h-6 text-yellow-400" />
        <div>
          <h1 className="text-lg font-bold text-soc-text">Contenedores del Lab</h1>
          <p className="text-xs text-soc-dim">
            Gestión de servicios Docker. Refresco automático cada 20 s.
          </p>
        </div>
      </div>

      <ContainerTable containers={containers} onRefresh={load} loading={loading} />
    </div>
  );
}
