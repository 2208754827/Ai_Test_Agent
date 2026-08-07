<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from "vue";
import { useSessionStore } from "../../stores/session";
import { useSessionHistoryStore } from "../../stores/sessionHistory";
import { useAppStore } from "../../stores/app";
import { t } from "../../services/i18n";
import SessionListItem from "./SessionListItem.vue";

const sessionStore = useSessionStore();
const historyStore = useSessionHistoryStore();
const appStore = useAppStore();

const listRef = ref<HTMLElement | null>(null);
const sentinelRef = ref<HTMLElement | null>(null);
let observer: IntersectionObserver | null = null;

function setupInfiniteScroll() {
  if (observer) observer.disconnect();
  if (!sentinelRef.value) return;
  observer = new IntersectionObserver(
    (entries) => {
      if (entries[0]?.isIntersecting && historyStore.hasMore && !historyStore.isLoading) {
        historyStore.loadMoreSessions();
      }
    },
    { root: listRef.value, threshold: 0.1 },
  );
  observer.observe(sentinelRef.value);
}

watch(
  () => historyStore.isPanelOpen,
  (open) => {
    if (open) {
      nextTick(() => setupInfiniteScroll());
    } else {
      if (observer) {
        observer.disconnect();
        observer = null;
      }
    }
  },
);

watch(
  () => historyStore.sessions.length,
  () => {
    nextTick(() => setupInfiniteScroll());
  },
);

onBeforeUnmount(() => {
  if (observer) {
    observer.disconnect();
    observer = null;
  }
});

async function handleSessionClick(sessionId: string) {
  if (sessionStore.isSwitching || sessionStore.session?.id === sessionId) return;
  await sessionStore.switchToSession(sessionId);
  historyStore.refreshSessions();
}

async function handleResume(sessionId: string) {
  if (sessionStore.isSwitching) return;
  await sessionStore.switchToSession(sessionId);
  await sessionStore.resumeCurrentSession();
  historyStore.refreshSessions();
}

async function handleNewChat() {
  if (sessionStore.isSwitching) return;
  await sessionStore.createAndSwitchToNewSession();
  historyStore.refreshSessions();
}
</script>

<template>
  <aside :class="['session-history-panel', { 'is-collapsed': !historyStore.isPanelOpen }]">
    <div class="session-history-inner">
      <div class="session-history-head">
        <span class="session-history-title">{{ t("sessionHistory.title") }}</span>
        <button class="session-new-btn" @click="handleNewChat" :disabled="sessionStore.isSwitching">
          <i class="fa-solid fa-plus"></i>
          {{ t("sessionHistory.new_chat") }}
        </button>
      </div>
      <div ref="listRef" class="session-history-list">
        <SessionListItem
          v-for="s in historyStore.sessions"
          :key="s.id"
          :session="s"
          :is-active="sessionStore.session?.id === s.id"
          @click="handleSessionClick(s.id)"
          @resume="handleResume(s.id)"
        />
        <div v-if="historyStore.isLoading" class="session-history-loading">
          <i class="fa-solid fa-spinner fa-spin"></i>
        </div>
        <div v-if="!historyStore.hasMore && historyStore.sessions.length > 0" class="session-history-all-loaded">
          {{ t("sessionHistory.all_loaded") }}
        </div>
        <div v-if="historyStore.error" class="session-history-error">
          {{ historyStore.error }}
        </div>
        <div ref="sentinelRef" class="session-history-sentinel"></div>
      </div>
    </div>
  </aside>
</template>
