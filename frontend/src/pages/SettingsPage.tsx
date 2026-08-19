import { useEffect, useState } from "react";
import { api } from "../api/client";
import { LoadingState } from "../components/Layout";
import { Bell, ShieldCheck, Mail } from "lucide-react";
import type { Settings, InstallationSettings, RepositorySettings } from "../types";

export function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // We keep a local draft state for email inputs so we don't save on every keystroke
  const [emailDrafts, setEmailDrafts] = useState<Record<string, string>>({});
  const [savingEmailFor, setSavingEmailFor] = useState<string | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = () => {
    setLoading(true);
    setError(null);
    api.getSettings()
      .then((data) => {
        setSettings(data);
        // Initialize drafts
        const drafts: Record<string, string> = {};
        data.installations.forEach(inst => {
          drafts[inst.id] = inst.notify_email || "";
        });
        setEmailDrafts(drafts);
      })
      .catch((err) => setError(err.message || "Failed to load settings"))
      .finally(() => setLoading(false));
  };

  const handleToggleNotify = async (inst: InstallationSettings) => {
    const newValue = !inst.notify_on_findings;
    try {
      // Optimistic update
      setSettings(prev => prev ? {
        ...prev,
        installations: prev.installations.map(i => i.id === inst.id ? { ...i, notify_on_findings: newValue } : i)
      } : null);
      await api.updateInstallation(inst.id, { notify_on_findings: newValue });
    } catch (e) {
      // Revert on error
      setSettings(prev => prev ? {
        ...prev,
        installations: prev.installations.map(i => i.id === inst.id ? { ...i, notify_on_findings: inst.notify_on_findings } : i)
      } : null);
      console.error(e);
    }
  };

  const handleSaveEmail = async (inst: InstallationSettings) => {
    const draft = emailDrafts[inst.id];
    if (draft === inst.notify_email) return;

    setSavingEmailFor(inst.id);
    try {
      const newEmail = draft.trim() === "" ? null : draft.trim();
      await api.updateInstallation(inst.id, { notify_email: newEmail });
      setSettings(prev => prev ? {
        ...prev,
        installations: prev.installations.map(i => i.id === inst.id ? { ...i, notify_email: newEmail } : i)
      } : null);
    } catch (e) {
      console.error(e);
      // Revert draft on error
      setEmailDrafts(prev => ({ ...prev, [inst.id]: inst.notify_email || "" }));
    } finally {
      setSavingEmailFor(null);
    }
  };

  const handleUpdateRepo = async (repo: RepositorySettings, updates: Partial<RepositorySettings>) => {
    try {
      // Optimistic update
      setSettings(prev => prev ? {
        ...prev,
        repositories: prev.repositories.map(r => r.id === repo.id ? { ...r, ...updates } : r)
      } : null);
      await api.updateRepository(repo.id, updates);
    } catch (e) {
      // Revert on error
      setSettings(prev => prev ? {
        ...prev,
        repositories: prev.repositories.map(r => r.id === repo.id ? repo : r) // revert to original
      } : null);
      console.error(e);
    }
  };

  if (loading) return <LoadingState label="Loading settings..." />;
  if (error) return <div className="text-[var(--color-critical)] p-8 text-center">{error}</div>;
  if (!settings) return null;

  return (
    <div className="space-y-12 pb-12 animate-in fade-in duration-500">
      
      {/* HEADER */}
      <div className="flex items-center gap-4 border-b border-[var(--color-border)] pb-6">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--color-scan)]/10">
          <Bell className="h-6 w-6 text-[var(--color-scan)]" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[var(--color-text)]">Settings</h1>
          <p className="text-[var(--color-text-muted)]">Manage your notification preferences and repository scan rules.</p>
        </div>
      </div>

      {/* INSTALLATIONS (NOTIFICATIONS) */}
      <section>
        <h2 className="mb-4 text-lg font-semibold flex items-center gap-2">
          <Mail className="h-5 w-5 text-[var(--color-text-muted)]" />
          Notification Preferences
        </h2>
        {settings.installations.length === 0 ? (
          <p className="text-sm text-[var(--color-text-muted)]">No GitHub installations found.</p>
        ) : (
          <div className="grid gap-6 sm:grid-cols-2">
            {settings.installations.map((inst) => (
              <div key={inst.id} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-sm">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-medium">
                    <span className="text-[var(--color-text-muted)] font-normal text-sm mr-2">Account:</span>
                    {inst.account_login}
                  </h3>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      className="sr-only peer"
                      checked={inst.notify_on_findings}
                      onChange={() => handleToggleNotify(inst)}
                    />
                    <div className="w-11 h-6 bg-[var(--color-border)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-transparent after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-transparent after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-[var(--color-scan)]"></div>
                  </label>
                </div>
                
                <div className={`transition-opacity ${inst.notify_on_findings ? "opacity-100" : "opacity-50 pointer-events-none"}`}>
                  <label className="block text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider mb-2">
                    Notification Email
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="email"
                      placeholder="security@example.com"
                      value={emailDrafts[inst.id]}
                      onChange={(e) => setEmailDrafts(prev => ({ ...prev, [inst.id]: e.target.value }))}
                      className="flex-1 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:border-[var(--color-scan)] focus:outline-none focus:ring-1 focus:ring-[var(--color-scan)]"
                    />
                    <button
                      onClick={() => handleSaveEmail(inst)}
                      disabled={savingEmailFor === inst.id || emailDrafts[inst.id] === (inst.notify_email || "")}
                      className="inline-flex items-center justify-center rounded bg-[var(--color-text)] px-4 py-2 text-sm font-medium text-[var(--color-bg)] transition-colors hover:bg-[var(--color-text-muted)] disabled:opacity-50"
                    >
                      {savingEmailFor === inst.id ? "Saving..." : "Save"}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* REPOSITORIES (SCAN RULES) */}
      <section>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-[var(--color-text-muted)]" />
            Repository Scan Rules
          </h2>
        </div>
        
        {settings.repositories.length === 0 ? (
          <p className="text-sm text-[var(--color-text-muted)]">No active repositories found.</p>
        ) : (
          <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-sm">
            <table className="w-full text-left text-sm">
              <thead className="bg-[var(--color-surface-raised)] text-xs uppercase text-[var(--color-text-muted)]">
                <tr>
                  <th className="px-6 py-4 font-medium">Repository</th>
                  <th className="px-6 py-4 font-medium">Enable Scans</th>
                  <th className="px-6 py-4 font-medium">Auto-Patching</th>
                  <th className="px-6 py-4 font-medium">Min Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {settings.repositories.map((repo) => (
                  <tr key={repo.id} className="transition-colors hover:bg-[var(--color-surface-raised)]/50">
                    <td className="px-6 py-4 font-medium">
                      {repo.full_name}
                    </td>
                    <td className="px-6 py-4">
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input 
                          type="checkbox" 
                          className="sr-only peer"
                          checked={repo.scan_enabled}
                          onChange={(e) => handleUpdateRepo(repo, { scan_enabled: e.target.checked })}
                        />
                        <div className="w-9 h-5 bg-[var(--color-border)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-transparent after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-transparent after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--color-scan)]"></div>
                      </label>
                    </td>
                    <td className="px-6 py-4">
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input 
                          type="checkbox" 
                          className="sr-only peer"
                          checked={repo.auto_patch_enabled}
                          onChange={(e) => handleUpdateRepo(repo, { auto_patch_enabled: e.target.checked })}
                          disabled={!repo.scan_enabled}
                        />
                        <div className={`w-9 h-5 bg-[var(--color-border)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-transparent after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-transparent after:border after:rounded-full after:h-4 after:w-4 after:transition-all ${repo.scan_enabled ? "peer-checked:bg-[var(--color-scan)]" : "opacity-50 cursor-not-allowed"}`}></div>
                      </label>
                    </td>
                    <td className="px-6 py-4">
                      <select
                        value={repo.min_severity_to_report}
                        onChange={(e) => handleUpdateRepo(repo, { min_severity_to_report: e.target.value as any })}
                        disabled={!repo.scan_enabled}
                        className="rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-sm focus:border-[var(--color-scan)] focus:outline-none focus:ring-1 focus:ring-[var(--color-scan)] disabled:opacity-50"
                      >
                        <option value="info">Info</option>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
