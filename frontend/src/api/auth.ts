import { api } from "./client";

export interface User {
  login: string;
  avatar_url: string;
}

export const authApi = {
  getMe: async (): Promise<User> => {
    const res = await fetch(`${api.baseUrl}/auth/me`, {
      headers: {
        Accept: "application/json",
      },
    });
    if (!res.ok) {
      throw new Error("Not authenticated");
    }
    return res.json();
  },
};
