<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { Label } from "@/components/ui/label";
import { OPEN_SOURCE_LICENSE_TEXT, OPEN_SOURCE_NOTICE_TEXT } from "@/lib/app/openSourceLicense";

const { t } = useI18n();

/**
 * LICENSE 与 NOTICE 的展示结构逐字相同，只有标题和正文不同。
 * 合并成一份数据 + v-for，避免两个 class 串在改样式时各改一处、慢慢漂移。
 */
const LEGAL_DOCUMENTS = [
  { label: "LICENSE", text: OPEN_SOURCE_LICENSE_TEXT },
  { label: "NOTICE", text: OPEN_SOURCE_NOTICE_TEXT },
];
</script>

<template>
  <details class="rounded-lg border">
    <summary class="cursor-pointer select-none p-4">
      <span class="flex flex-col gap-1">
        <Label>{{ t("settings.openSourceLicenseTitle") }}</Label>
        <span class="text-sm text-muted-foreground">{{ t("settings.openSourceLicenseDescription") }}</span>
      </span>
    </summary>
    <div class="grid gap-4 border-t px-4 py-4 lg:grid-cols-2">
      <div v-for="legalDocument in LEGAL_DOCUMENTS" :key="legalDocument.label" class="min-w-0">
        <div class="mb-2 font-mono text-xs font-medium text-muted-foreground">{{ legalDocument.label }}</div>
        <pre class="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/30 p-3 font-mono text-[11px] leading-relaxed text-foreground">{{ legalDocument.text }}</pre>
      </div>
    </div>
  </details>
</template>
