<script setup lang="ts">
import { computed } from "vue";
import type { SessionSummary } from "../../types";
import { t } from "../../services/i18n";

const props = defineProps<{
  session: SessionSummary;
  isActive: boolean;
}>();

const emit = defineEmits<{
  click: [];
  resume: [];
  delete: [];
}>();

const truncatedTitle = computed(() => {
  const title = props.session.title || t("sessionHistory.untitled");
  return title.length > 28 ? title.slice(0, 26) + "..." : title;
});

const statusLabel = computed(() => {
  const map: Record<string, string> = {
    running: t("runtime.running"),
    waiting_approval: t("runtime.waiting_approval"),
    interrupted: t("runtime.interrupted"),
    completed: t("runtime.completed"),
    failed: t("runtime.failed"),
    idle: t("runtime.idle"),
  };
  return map[props.session.status] || props.session.status;
});

const relativeTime = computed(() => {
  const then = Date.parse(props.session.updated_at);
  if (!Number.isFinite(then)) return "";
  const diffMs = Date.now() - then;
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return t("sessionHistory.just_now");
  if (diffMin < 60) return `${diffMin}${t("sessionHistory.minutes_ago")}`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}${t("sessionHistory.hours_ago")}`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}${t("sessionHistory.days_ago")}`;
});

const isResumable = computed(
  () => props.session.status === "interrupted" || props.session.status === "failed",
);

const canResume = computed(() => {
  // SessionSummary doesn't carry is_resumable; use status as best-effort.
  // The store's resumeCurrentSession() will check the authoritative flag
  // from SessionDetail and show an error if the session is not actually resumable.
  return isResumable.value;
});

const isDeletable = computed(
  () => props.session.status !== "running" && props.session.status !== "waiting_approval",
);

function handleDelete() {
  if (!window.confirm(t("sessionHistory.delete_confirm"))) return;
  emit("delete");
}
</script>

<template>
  <div
    :class="['session-list-item', { 'is-active': isActive }]"
    @click="emit('click')"
  >
    <div class="session-list-item-title">{{ truncatedTitle }}</div>
    <div class="session-list-item-meta">
      <span :class="['session-status-dot', `is-${session.status}`]"></span>
      <span class="session-status-label">{{ statusLabel }}</span>
      <span class="session-time-label">{{ relativeTime }}</span>
    </div>
    <button
      v-if="isResumable"
      class="session-resume-btn"
      @click.stop="emit('resume')"
    >
      <i class="fa-solid fa-play"></i>
      {{ t("sessionHistory.resume") }}
    </button>
    <button
      v-if="isDeletable"
      class="session-delete-btn"
      :title="t('sessionHistory.delete')"
      @click.stop="handleDelete"
    >
      <i class="fa-solid fa-trash-can"></i>
    </button>
  </div>
</template>
