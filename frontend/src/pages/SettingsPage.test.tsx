import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SettingsPage } from './SettingsPage';
import { BrowserRouter } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../components/AuthProvider';
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../api/client', () => ({
  api: {
    getSettings: vi.fn(),
    updateInstallation: vi.fn(),
    updateRepository: vi.fn(),
  }
}));

vi.mock('../components/AuthProvider', () => ({
  useAuth: vi.fn(),
}));

const mockSettings = {
  installations: [
    {
      id: 'inst-1',
      account_login: 'testorg',
      notify_on_findings: true,
      notify_email: 'sec@testorg.com',
    }
  ],
  repositories: [
    {
      id: 'repo-1',
      full_name: 'testorg/repo1',
      scan_enabled: true,
      auto_patch_enabled: false,
      min_severity_to_report: 'medium',
    }
  ]
};

describe('SettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getSettings as any).mockResolvedValue(mockSettings);
    (useAuth as any).mockReturnValue({
      user: { login: 'testuser', avatar_url: 'test.jpg', installations: [] },
      isLoading: false
    });
    // Suppress console.error in tests
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  const renderComponent = () => render(
    <BrowserRouter>
      <SettingsPage />
    </BrowserRouter>
  );

  it('renders loading state initially and then displays settings', async () => {
    renderComponent();
    
    // It should load the installation and repo
    expect(await screen.findByText('testorg')).toBeInTheDocument();
    expect(await screen.findByText('testorg/repo1')).toBeInTheDocument();
  });

  it('handles optimistic update and rollback for notification toggle', async () => {
    renderComponent();
    
    const checkbox = await screen.findByRole('checkbox', { name: /Toggle notifications for testorg/i });
    expect(checkbox).toBeChecked();

    // Mock API failure
    (api.updateInstallation as any).mockRejectedValueOnce(new Error('API Error'));

    fireEvent.click(checkbox);
    
    // Optimistic update should uncheck it immediately
    expect(checkbox).not.toBeChecked();

    // After API failure, it should rollback
    await waitFor(() => {
      expect(checkbox).toBeChecked();
    });
  });

  it('handles optimistic update and rollback for repository scan toggle', async () => {
    renderComponent();
    
    const scanToggle = await screen.findByRole('checkbox', { name: /Toggle scan enabled for testorg\/repo1/i });
    expect(scanToggle).toBeChecked();

    (api.updateRepository as any).mockRejectedValueOnce(new Error('API Error'));

    fireEvent.click(scanToggle);
    expect(scanToggle).not.toBeChecked();

    await waitFor(() => {
      expect(scanToggle).toBeChecked();
    });
  });

  it('handles optimistic update and rollback for email change', async () => {
    renderComponent();
    
    const emailInput = await screen.findByDisplayValue('sec@testorg.com');
    const saveButton = await screen.findByRole('button', { name: /save/i });

    (api.updateInstallation as any).mockRejectedValueOnce(new Error('API Error'));

    fireEvent.change(emailInput, { target: { value: 'new@testorg.com' } });
    fireEvent.click(saveButton);

    // After API failure, the input should revert back to original
    await waitFor(() => {
      expect(emailInput).toHaveValue('sec@testorg.com');
    });
  });
});
