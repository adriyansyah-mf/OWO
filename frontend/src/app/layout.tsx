import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/contexts/AuthContext';
import { SearchProvider } from '@/contexts/SearchContext';
import AppShell from '@/components/AppShell';

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
          <SearchProvider>
            <AppShell>{children}</AppShell>
          </SearchProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
