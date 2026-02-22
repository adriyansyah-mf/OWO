import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/contexts/AuthContext';
import { AlertStreamProvider } from '@/contexts/AlertStreamContext';
import { SearchProvider } from '@/contexts/SearchContext';
import AppShell from '@/components/AppShell';
import AlertToastContainer from '@/components/AlertToast';

export const metadata: Metadata = {
  title: 'OWO — Open Workstation Observer',
  description: 'Endpoint Detection & Response',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <AlertStreamProvider>
            <SearchProvider>
              <AppShell>{children}</AppShell>
              <AlertToastContainer />
            </SearchProvider>
          </AlertStreamProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
