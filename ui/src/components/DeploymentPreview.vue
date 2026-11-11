<script setup>
import ServiceDestination from './ServiceDestination.vue';
defineProps({ plan: { type: Object, required: true }, busy: Boolean, rollback: Boolean });
defineEmits(['confirm', 'refresh', 'cancel']);
function date(value) { return value ? new Date(value).toLocaleString('zh-CN', {timeZone:'Asia/Shanghai',hour12:false}) : '—'; }
</script>

<template>
 <div class="deployment-preview">
  <p class="hint">{{ rollback?'将回退到以下历史版本，并关闭此目标的自动部署。':'将使用以下证书版本更新列出的目标。' }}任务入队后可在「任务记录」查看执行和生效检查结果。</p>
  <div class="preview-certificate"><strong>{{ plan.certificate.name }}</strong><span>{{ plan.version?.domains.join(' · ') || plan.certificate.domains.join(' · ') }}</span><span>到期：{{ date(plan.version?.not_after) }}</span><span>版本：<code>{{ plan.version?.id || '暂无版本' }}</code></span><span>SHA256：<code>{{ plan.version?.fingerprint || '—' }}</code></span></div>
  <h3>本次更新 {{ plan.target_count }} 个目标</h3>
  <div v-if="plan.targets.length" class="table-wrap"><table class="relationship-table"><thead><tr><th>服务 / 域名</th><th>实际更新位置</th><th>校验结果</th></tr></thead><tbody><tr v-for="t in plan.targets" :key="t.id"><td><strong>{{ t.name }}</strong><small>{{ t.domain }}</small><small v-if="t.destination.cloud_scope !== t.domain">云端范围：{{ t.destination.cloud_scope }}</small></td><td><ServiceDestination :destination="t.destination" /></td><td><span :class="['badge',t.reason?'bad':'good']">{{ t.reason?'需要处理':'可以部署' }}</span><small v-if="t.reason" class="danger">{{ t.reason }}</small></td></tr></tbody></table></div>
  <div v-if="plan.blockers.length" class="error" role="alert"><strong>暂不能提交部署</strong><ul><li v-for="reason in plan.blockers" :key="reason">{{ reason }}</li></ul></div>
  <details v-if="plan.skipped.length"><summary>本次不更新的绑定目标 · {{ plan.skipped.length }}</summary><ul class="preview-skipped"><li v-for="t in plan.skipped" :key="t.id"><strong>{{ t.name }}</strong> · {{ t.domain }}<span>{{ t.reason }}</span></li></ul></details>
  <p class="relationship-source">此预览保留 10 分钟。证书版本、绑定或部署配置变化后需要刷新确认。</p>
  <div class="form-actions"><button :disabled="busy" @click="$emit('cancel')">取消</button><button :disabled="busy" @click="$emit('refresh')">刷新影响范围</button><button class="primary" :disabled="busy || !plan.can_submit" @click="$emit('confirm')">{{ rollback?'确认回退':'确认部署' }} · {{ plan.target_count }} 个目标</button></div>
 </div>
</template>
