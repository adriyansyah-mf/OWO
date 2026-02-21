'use client';

import { createContext, useContext, useState } from 'react';

type SearchContextType = {
  query: string;
  setQuery: (q: string) => void;
};

const SearchContext = createContext<SearchContextType | null>(null);

export function SearchProvider({ children }: { children: React.ReactNode }) {
  const [query, setQuery] = useState('');
  return (
    <SearchContext.Provider value={{ query, setQuery }}>
      {children}
    </SearchContext.Provider>
  );
}

export function useSearch() {
  const ctx = useContext(SearchContext);
  return ctx ?? { query: '', setQuery: () => {} };
}
