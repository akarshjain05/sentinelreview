import React, { createContext, useContext, useEffect, useState } from "react";
import { User, authApi } from "../api/auth";
import { LoadingState } from "./Layout";

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType>({ user: null, isLoading: true });

export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    authApi
      .getMe()
      .then((user) => setUser(user))
      .catch(() => setUser(null))
      .finally(() => setIsLoading(false));
  }, []);

  if (isLoading) {
    return <LoadingState label="Checking authentication" />;
  }

  return <AuthContext.Provider value={{ user, isLoading }}>{children}</AuthContext.Provider>;
}
