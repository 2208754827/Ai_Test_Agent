import { defineStore } from "pinia";

import { api } from "../services/api";
import type { SessionSummary } from "../types";
import { useSessionStore } from "./session";

export const useSessionHistoryStore = defineStore("sessionHistory", {
  state: () => ({
    sessions: [] as SessionSummary[],
    isLoading: false,
    error: "",
    offset: 0,
    hasMore: true,
    isPanelOpen: false,
  }),
  actions: {
    async loadSessions() {
      this.isLoading = true;
      this.error = "";
      try {
        const page = await api.listSessionsPage(20, 0);
        this.sessions = page.items;
        this.offset = page.items.length;
        this.hasMore = page.has_more;
      } catch (e) {
        this.error = e instanceof Error ? e.message : "加载会话列表失败。";
      } finally {
        this.isLoading = false;
      }
    },
    async loadMoreSessions() {
      if (!this.hasMore || this.isLoading) return;
      this.isLoading = true;
      try {
        const page = await api.listSessionsPage(20, this.offset);
        this.sessions = [...this.sessions, ...page.items];
        this.offset += page.items.length;
        this.hasMore = page.has_more;
      } catch (e) {
        this.error = e instanceof Error ? e.message : "加载更多会话失败。";
      } finally {
        this.isLoading = false;
      }
    },
    async refreshSessions() {
      this.offset = 0;
      await this.loadSessions();
    },
    async deleteSession(sessionId: string) {
      try {
        await api.deleteSession(sessionId);
        const idx = this.sessions.findIndex((s) => s.id === sessionId);
        if (idx !== -1) {
          this.sessions.splice(idx, 1);
          this.offset = Math.max(0, this.offset - 1);
        }
        // If the deleted session is the active one, clear the session store.
        const sessionStore = useSessionStore();
        sessionStore.handleSessionDeleted(sessionId);
      } catch (e) {
        this.error = e instanceof Error ? e.message : "删除会话失败。";
        throw e;
      }
    },
    togglePanel() {
      this.isPanelOpen = !this.isPanelOpen;
      if (this.isPanelOpen && this.sessions.length === 0) {
        this.loadSessions();
      }
    },
    setPanelOpen(open: boolean) {
      this.isPanelOpen = open;
      if (open && this.sessions.length === 0) {
        this.loadSessions();
      }
    },
  },
});
