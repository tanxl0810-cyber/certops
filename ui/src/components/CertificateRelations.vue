<script setup>
import { computed, ref } from 'vue';
import ServiceDestination from './ServiceDestination.vue';

const props = defineProps({ graph: { type: Object, required: true }, selectedId: String, busy: Boolean });
const emit = defineEmits(['select', 'configure', 'deploy', 'certificate-config']);
const query = ref(''), filter = ref('all');
const certificates = computed(() => props.graph.certificates || []);
const selected = computed(() => certificates.value.find(c => c.id === props.selectedId) || certificates.value[0]);
const visibleCertificates = computed(() => certificates.value.filter(c => `${c.name} ${c.domains.join(' ')}`.toLowerCase().includes(query.value.toLowerCase())));
const matches = row => filter.value === 'all' || row.kind === filter.value;
const bindings = computed(() => (selected.value?.bindings || []).filter(matches));
const unbound = computed(() => (selected.value?.unbound || []).filter(matches));
const products = computed(() => [...new Map([...(selected.value?.bindings || []), ...(selected.value?.unbound || [])].map(r => [r.kind, r.destination.product])).entries()]);
function date(value) { return value ? new Date(value).toLocaleString('zh-CN', {timeZone:'Asia/Shanghai', hour12:false}) : '—'; }
function select(id) { filter.value = 'all'; emit('select', id); }
function configure(row) { emit('configure', { target_id: row.target_id, certificate_id: row.binding === 'unbound' ? selected.value.id : null }); }
function evidence(row) {
 const values = [];
 if (row.tls) values.push(`TLS 已核实${row.tls.is_latest ? '最新版本' : '历史版本'}`);
 if (row.cloud.length) values.push(`云端使用${row.cloud.every(c => c.is_latest) ? '最新版本' : '含历史版本'}`);
 return values.length ? values.join(' · ') : '尚未核实使用此证书';
}
</script>

<template>
 <div v-if="!certificates.length" class="panel empty"><h3>先导入或上传一张证书</h3><p>这里会按证书展示已绑定服务、实际使用情况和更新范围。</p></div>
 <div v-else class="relationship-layout">
  <aside class="panel certificate-picker">
   <label for="relationship-search">选择要查看的证书</label>
   <input id="relationship-search" v-model="query" type="search" placeholder="搜索名称或域名">
   <div class="certificate-options">
    <button v-for="c in visibleCertificates" :key="c.id" :class="{selected:selected?.id === c.id}" :aria-pressed="selected?.id === c.id" @click="select(c.id)">
     <strong>{{ c.name }}</strong><span>{{ c.domains.join(' · ') || '等待证书版本' }}</span>
     <small>手动 {{ c.summary.manual }} · 自动 {{ c.summary.automatic }} · 云端关联 {{ c.summary.cloud }}</small>
    </button>
    <p v-if="!visibleCertificates.length" class="muted">没有匹配的证书</p>
   </div>
  </aside>
  <div v-if="selected" class="relationship-detail">
   <section class="panel relationship-certificate">
    <div class="relationship-title"><div><span class="eyebrow">证书 → 服务 / 机器</span><h2>{{ selected.name }}</h2><p>{{ selected.domains.join(' · ') }}</p></div><button @click="emit('certificate-config', selected.id)">证书配置</button></div>
    <div class="relationship-version"><span>最新版本到期：{{ date(selected.latest_version?.not_after) }}</span><span>SHA256：<code>{{ selected.latest_version?.fingerprint || '暂无版本' }}</code></span></div>
    <div class="relationship-stats">
     <div><strong>{{ selected.summary.manual }}</strong><span>手动部署范围</span></div>
     <div><strong>{{ selected.summary.automatic }}</strong><span>新版本自动更新</span></div>
     <div><strong>{{ selected.summary.cloud }}</strong><span>云端证书关联</span></div>
     <div><strong>{{ selected.summary.unbound }}</strong><span>使用中但未绑定此证书</span></div>
    </div>
    <p class="relationship-explanation">手动部署会更新已启用的绑定目标；新版本自动更新还需证书和目标同时开启自动部署。上传或续签产生新版本后，校验通过才会执行。</p>
    <div v-if="!selected.summary.bound && selected.summary.cloud" class="relationship-notice">这张证书在云端有 {{ selected.summary.cloud }} 条使用关联，目前尚未绑定任何部署目标。更新证书库后，这些服务不会自动更新；请逐项核对下方服务并保存绑定。</div>
    <div v-else-if="!selected.summary.automatic" class="relationship-notice">当前自动更新范围为 0。保存新版本后，可点击「预览手动部署」确认更新目标。</div>
    <div class="relationship-actions"><button class="primary" :disabled="busy || !selected.summary.manual" @click="emit('deploy', selected.id)">预览手动部署 · {{ selected.summary.manual }} 个目标</button><span v-if="selected.summary.skipped" class="muted">另有 {{ selected.summary.skipped }} 个绑定目标已停用、排除或仅监控</span></div>
   </section>
   <div class="relationship-filter"><span>服务与机器清单</span><select v-model="filter" aria-label="筛选关联产品"><option value="all">全部产品</option><option v-for="[kind,label] in products" :key="kind" :value="kind">{{ label }}</option></select></div>
   <section class="panel relationship-services">
    <div class="panel-head"><h3>已保存的部署绑定 · {{ bindings.length }}</h3><span>决定这张证书将更新哪些目标</span></div>
    <div v-if="!bindings.length" class="empty compact"><h3>暂无匹配的部署绑定</h3><p>在下方使用清单中选择目标，或到「部署目标」添加并绑定。</p></div>
    <div v-else class="table-wrap"><table class="relationship-table"><thead><tr><th>服务 / 域名</th><th>实际更新位置</th><th>新版本如何更新</th><th>当前使用证据</th><th>操作</th></tr></thead><tbody>
     <tr v-for="r in bindings" :key="r.id"><td><strong>{{ r.name }}</strong><small>{{ r.domain }}</small><small v-if="r.destination.cloud_scope !== r.domain">云端范围：{{ r.destination.cloud_scope }}</small></td>
      <td><ServiceDestination :destination="r.destination" /></td>
      <td><span :class="['badge',r.automatic_on_new_version?'good':r.manual_included?'warn':'']">{{ r.automatic_on_new_version?'新版本自动更新':r.manual_included?'仅手动部署':'本次不更新' }}</span><small v-if="r.manual_reason" class="warning">{{ r.manual_reason }}</small><small v-else>部署前会校验最新版本、域名和私钥</small></td>
      <td><span>{{ evidence(r) }}</span><small v-if="r.status.actual_certificate_name && !r.tls">实际证书：{{ r.status.actual_certificate_name }}</small><small v-if="r.tls">TLS 核实：{{ date(r.tls.checked_at) }}</small><small v-if="r.cloud.length">云端同步：{{ date(r.cloud[0].synced_at) }}</small></td>
      <td><button :disabled="busy || r.excluded" @click="configure(r)">配置绑定</button></td></tr>
    </tbody></table></div>
   </section>
   <section class="panel relationship-services">
    <div class="panel-head"><h3>正在使用，但未绑定此证书 · {{ unbound.length }}</h3><span>更新此证书时不会自动包含</span></div>
    <div v-if="!unbound.length" class="empty compact"><p>已同步的云端关联和 TLS 检查中，未发现其他使用此证书的服务。</p></div>
    <div v-else class="table-wrap"><table class="relationship-table"><thead><tr><th>服务 / 域名</th><th>机器 / 云资源</th><th>部署绑定状态</th><th>当前使用证据</th><th>操作</th></tr></thead><tbody>
     <tr v-for="r in unbound" :key="r.id"><td><strong>{{ r.name }}</strong><small>{{ r.domain }}</small><small v-if="r.destination.cloud_scope !== r.domain">云端范围：{{ r.destination.cloud_scope }}</small></td>
      <td><ServiceDestination :destination="r.destination" /></td>
      <td><span class="badge">{{ r.excluded?'已排除':r.binding==='other'?'已绑定其他证书':r.binding==='missing'?'尚未建立目标':'未绑定' }}</span><small v-if="r.bound_certificate_name">后续更新使用：{{ r.bound_certificate_name }}</small><small v-if="r.configuration_required">待填写具体域名 / 探测配置</small></td>
      <td><span>{{ evidence(r) }}</span><small v-if="r.tls">TLS 核实：{{ date(r.tls.checked_at) }}</small><small v-if="r.cloud.length">云端同步：{{ date(r.cloud[0].synced_at) }}</small></td>
      <td><button :disabled="busy || !r.target_id || r.excluded" @click="configure(r)">{{ r.binding==='unbound'?'绑定此证书':'查看目标配置' }}</button><small v-if="r.binding==='unbound'">核对配置并保存后生效</small></td></tr>
    </tbody></table></div>
   </section>
   <p class="relationship-source">使用关系按证书指纹匹配，包含历史版本；域名覆盖相同的不同证书分别展示。云端关联以最近同步结果为准，TLS 以最近检查为准。刷新云端清单请到「部署目标 → 发现阿里云资源」。</p>
   <p v-if="graph.metadata_pending?.length" class="hint">{{ graph.metadata_pending.join('、') }} 的历史快照尚无证书指纹，请重新发现阿里云资源后查看完整关联。</p>
  </div>
 </div>
</template>
