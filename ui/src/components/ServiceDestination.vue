<script setup>
defineProps({ destination: { type: Object, required: true } });
</script>

<template>
 <div class="service-destination">
  <strong>{{ destination.product }}</strong>
  <span v-if="destination.machine">主机：<code>{{ destination.machine }}</code></span>
  <span v-if="destination.resource_id && destination.resource_id !== destination.machine">资源：<code>{{ destination.resource_id }}</code></span>
  <span v-if="destination.pipeline_id">云效流水线：<code>{{ destination.pipeline_id }}</code></span>
  <span v-if="destination.listener_id">监听器 / 证书位置：<code>{{ destination.listener_id }}</code></span>
  <span v-if="destination.address">探测地址：<code>{{ destination.address }}:{{ destination.port }}</code></span>
  <span v-else>HTTPS 端口：{{ destination.port || 443 }}</span>
  <span v-if="destination.certificate_path">证书：<code>{{ destination.certificate_path }}</code></span>
  <span v-if="destination.private_key_path">私钥：<code>{{ destination.private_key_path }}</code></span>
  <span class="muted">{{ destination.region || '全局' }} · {{ destination.operation }}</span>
 </div>
</template>
