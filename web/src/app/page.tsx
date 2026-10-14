'use client';

import React, { useState, useEffect, useCallback } from 'react';
import MainLayout from '@/components/reconx/main-layout';
import NewScanForm from '@/components/reconx/new-scan-form';
import ScanProgress from '@/components/reconx/scan-progress';
import ResultsDashboard from '@/components/reconx/results-dashboard';
import ScanHistory from '@/components/reconx/scan-history';
import GuidePage from '@/components/reconx/guide-page';
import type { ViewMode, ScanConfig, ScanMetadata } from '@/lib/reconx-types';
import { useToast } from '@/hooks/use-toast';

export default function Home() {
  const { toast } = useToast();
  const [activeView, setActiveView] = useState<ViewMode>('new-scan');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [runningScanId, setRunningScanId] = useState<string | null>(null);
  const [historyRefreshKey, setHistoryRefreshKey] = useState(0);

  // Poll for running scans on mount and periodically
  useEffect(() => {
    const checkRunning = async () => {
      try {
        const res = await fetch('/api/scans');
        if (res.ok) {
          const data = await res.json();
          const running = (data.scans || []).find(
            (s: ScanMetadata) => s.status === 'running'
          );
          setRunningScanId(running?.id || null);
        }
      } catch {
        // silent
      }
    };

    checkRunning();
    const interval = setInterval(checkRunning, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStartScan = useCallback(async (config: ScanConfig) => {
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });

      if (res.ok) {
        const data = await res.json();
        toast({
          title: 'Scan launched',
          description: `Scan ${data.scanId} started successfully.`,
        });
        setSelectedScanId(data.scanId);
        setRunningScanId(data.scanId);
        setActiveView('progress');
      } else {
        const data = await res.json();
        toast({
          title: 'Failed to start scan',
          description: data.error || 'Unknown error occurred.',
          variant: 'destructive',
        });
      }
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to communicate with the server.',
        variant: 'destructive',
      });
    }
  }, [toast]);

  const handleViewResults = useCallback((scanId: string) => {
    setSelectedScanId(scanId);
    setActiveView('results');
  }, []);

  const handleViewProgress = useCallback((scanId: string) => {
    setSelectedScanId(scanId);
    setActiveView('progress');
  }, []);

  const handleBackFromProgress = useCallback(() => {
    setActiveView('new-scan');
    setHistoryRefreshKey((k) => k + 1);
  }, []);

  const handleBackFromResults = useCallback(() => {
    setActiveView('history');
    setHistoryRefreshKey((k) => k + 1);
  }, []);

  return (
    <MainLayout
      activeView={activeView}
      onViewChange={setActiveView}
      runningScanId={runningScanId}
    >
      {activeView === 'new-scan' && (
        <NewScanForm onStartScan={handleStartScan} />
      )}

      {activeView === 'history' && (
        <ScanHistory
          onViewResults={handleViewResults}
          onViewProgress={handleViewProgress}
          onRefresh={() => setHistoryRefreshKey((k) => k + 1)}
        />
      )}

      {activeView === 'progress' && selectedScanId && (
        <ScanProgress
          scanId={selectedScanId}
          onViewResults={handleViewResults}
          onBack={handleBackFromProgress}
        />
      )}

      {activeView === 'results' && selectedScanId && (
        <ResultsDashboard
          scanId={selectedScanId}
          onBack={handleBackFromResults}
        />
      )}

      {activeView === 'guide' && (
        <GuidePage />
      )}
    </MainLayout>
  );
}
