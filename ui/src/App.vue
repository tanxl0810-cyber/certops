<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue';
import CertificateRelations from './components/CertificateRelations.vue';
import DeploymentPreview from './components/DeploymentPreview.vue';
import ServiceDestination from './components/ServiceDestination.vue';

const user = ref(null), loading = ref(true), busy = ref(false), page = ref('overview');
const csrf = ref(''), error = ref(''), toast = ref(''), modal = ref(null), form = ref({});
const dashboard = ref({}), certs = ref([]), targets = ref([]), credentials = ref([]), jobs = ref([]), audit = ref([]), trash = ref([]);
const notification = ref({settings:{enabled:false,credential_id:null,days:[30,15,7,3,1]},alerts:[]});
const catalog = ref({targets:{},issuer_v1:{},issuer_v2:{}}), search = ref(''), productFilter = ref(''), targetVisibility = ref('managed');
const loginForm = reactive({username:'admin',password:''}), passwordForm = reactive({current_password:'',password:''});
const authOptions = ref({feishu:false});
const associations=ref({resources:[],snapshots:[]}), associationCertificate=ref('');
const relationGraph=ref({certificates:[],target_status:{},metadata_pending:[]}), selectedRelation=ref('');
const relationIndex=computed(()=>new Map(relationGraph.value.certificates.map(c=>[c.id,c])));
function relationSummary(id){return relationIndex.value.get(id)?.summary||{bound:0,manual:0,automatic:0,cloud:0};}
function showRelations(row){selectedRelation.value=row.id;go('relations');}
function configureRelationship({target_id,certificate_id}){
 const target=targets.value.find(t=>t.id===target_id);if(!target)return;
 newTarget(target);
 if(certificate_id&&!target.certificate_id){form.value.certificate_id=certificate_id;form.value.auto_deploy=false;}
}
function configureRelationCertificate(id){const row=certs.value.find(c=>c.id===id);if(row)newCertificate(row);}
function actualCertificate(target){return relationGraph.value.target_status[target.id]?.actual_certificate_name||(target.checked_at?'未匹配证书库':'尚未检查');}
const noticeDays = ref('30,15,7,3,1');
const discoveryRegions=[{id:'cn-shenzhen',label:'华南 · 深圳'},{id:'cn-hangzhou',label:'华东 · 杭州'},{id:'cn-hongkong',label:'中国香港'}];
const scanRegions=computed(()=>[...new Set([...(form.value.regions||[]),...(form.value.regionsText||'').split(/[\s,，]+/).filter(Boolean)])]);
const nav = [ ['overview','◫','总览'],['certificates','◇','证书管理'],['relations','⇄','证书与服务'],['targets','▤','部署目标'],
 ['credentials','⌘','访问凭据'],['jobs','↗','任务记录'],['notifications','♧','飞书通知'],['audit','≡','操作审计'],['trash','⌫','回收站'] ];
const currentTitle = computed(() => nav.find(n=>n[0]===page.value)?.[2] || '总览');
const stateNames = {queued:'排队中',running:'执行中',waiting:'等待中',failed:'失败',succeeded:'已完成',
 cancelled:'已取消',pending:'待申请',applying:'申请中',validating:'待验证',issued:'已签发',sent:'已发送'};
const kindNames = {deploy:'部署证书',probe:'TLS 检查',issue:'申请证书',discover:'发现资源',aliyun:'阿里云',ssh:'SSH 主机',feishu:'飞书 Webhook',yunxiao:'云效流水线'};
const labels = {instance_id:'实例 ID',listener_id:'监听器 ID',accelerator_id:'加速实例 ID',certificate_role:'证书位置',
 api_version:'接口版本',resource_instance_id:'接入资源实例 ID',resource_product:'接入产品类型（clb4 / clb7 / ecs / nlb）',port:'接入 HTTPS 端口',replace_certificate_id:'待替换证书 ID（如 123-cn-hangzhou）',bucket:'Bucket 名称',previous_cert_id:'当前证书 ID（可选）',load_balancer_id:'CLB 实例 ID',
 listener_port:'HTTPS 监听端口',domain_extension_id:'扩展域名 ID（默认监听器留空）',certificate_path:'证书文件绝对路径',
 private_key_path:'私钥文件绝对路径',test_command:'Nginx 配置检查命令',reload_command:'Nginx 重载命令',pipeline_id:'云效流水线 ID',machine_id:'主机唯一标识（物理机 IP / 名称）',check_interval_hours:'流水线巡检间隔（小时）'};
let timer, toastTimer;

function clone(value){return JSON.parse(JSON.stringify(value));}
function date(v){return v?new Date(v).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—';}
function short(v){return v?`${v.slice(0,8)}…${v.slice(-6)}`:'—';}
function showToast(text){toast.value=text;clearTimeout(toastTimer);toastTimer=setTimeout(()=>toast.value='',5000);}
function certName(id){return certs.value.find(c=>c.id===id)?.name||trash.value.find(c=>c.kind==='certificate'&&c.resource_id===id)?.name||(id?'已删除证书':'未绑定');}
function targetName(id){return targets.value.find(t=>t.id===id)?.name||'—';}
function credName(id){return credentials.value.find(c=>c.id===id)?.name||'—';}
function productLabel(kind){return catalog.value.targets[kind]?.label||kind;}
function stateLabel(state){return stateNames[state]||state;}
function statusClass(state){return ['succeeded','issued','sent'].includes(state)?'good':state==='failed'?'bad':'warn';}
function remaining(value){return value==null?'未检查':value<0?`已过期 ${Math.abs(value)} 天`:`${value} 天`;}
function daysClass(v){return v==null?'muted':v<7?'danger':v<=30?'warning':'success';}
function modalClose(){modal.value=null;form.value={};error.value='';}

async function api(path,method='GET',body){
 const r=await fetch('/api'+path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json',
  ...(csrf.value?{'X-CSRF-Token':csrf.value}:{})},body:body===undefined?undefined:JSON.stringify(body)});
 let data;try{data=await r.json()}catch{data={detail:'服务返回异常，请稍后重试'}}
 if(!r.ok){if(r.status===401)user.value=null;throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));}
 return data;
}
async function run(fn){if(busy.value)return;busy.value=true;error.value='';try{await fn()}catch(e){error.value=e.message}finally{busy.value=false}}
async function refresh(){
 const data=await Promise.all([api('/dashboard'),api('/certificates'),api('/targets'),api('/credentials'),api('/jobs'),api('/notifications'),api('/trash'),api('/cloud-resources'),api('/relationships')]);
 [dashboard.value,certs.value,targets.value,credentials.value,jobs.value,notification.value,trash.value,associations.value,relationGraph.value]=data;
 noticeDays.value=notification.value.settings.days.join(',');
 if(page.value==='audit')audit.value=await api('/audit');
}
async function boot(){
 try{authOptions.value=await api('/auth/options')}catch{}
 const loginError=new URLSearchParams(location.search).get('feishu_error');
 if(loginError){
  const messages={member_denied:'当前账号未获本系统授权，请联系管理员。',tenant_denied:'当前飞书账号不属于已授权的企业。',state_invalid:'登录校验已失效，请重新使用飞书登录。',cancelled:'已取消飞书授权。',authorization_unavailable:'成员授权服务暂不可用，请稍后重试。'};
  error.value=messages[loginError]||'飞书登录未完成，请重新尝试或联系管理员检查应用配置。';
  history.replaceState(null,'',location.pathname);
 }
 try{const data=await api('/session');user.value=data;csrf.value=data.csrf;if(!data.must_change){catalog.value=await api('/catalog');await refresh();}}
 catch(e){if(user.value)error.value=e.message}finally{loading.value=false}
}
async function login(){await run(async()=>{const data=await api('/login','POST',loginForm);user.value=data;csrf.value=data.csrf;
 loginForm.password='';if(!data.must_change){catalog.value=await api('/catalog');await refresh();}})}
async function logout(){await run(async()=>{await api('/logout','POST',{});user.value=null;csrf.value='';modalClose();})}
async function changePassword(){await run(async()=>{await api('/password','POST',passwordForm);passwordForm.current_password='';passwordForm.password='';
 user.value.must_change=false;catalog.value=await api('/catalog');await refresh();modalClose();showToast('密码已更新，其他会话已退出');})}
async function go(key){page.value=key;search.value='';error.value='';if(key==='audit')await run(async()=>audit.value=await api('/audit'));}

const selectedBinding=computed(()=>certs.value.find(c=>c.id===form.value.certificate_id));
async function reviewDelete(collection,row){await run(async()=>{
 const preview=await api('/'+collection+'/'+row.id+'/deletion-check');
 form.value={...preview,collection};modal.value='delete';
});}
async function deleteResource(){await run(async()=>{
 const f=form.value;
 try{await api('/'+f.collection+'/'+f.id,'DELETE');}
 catch(e){Object.assign(f,await api('/'+f.collection+'/'+f.id+'/deletion-check'));throw e;}
 modalClose();await refresh();showToast('已移入回收站，可在回收站恢复');
});}
async function restoreResource(row){await run(async()=>{
 await api('/trash/'+row.kind+'/'+row.resource_id+'/restore','POST',{});await refresh();
 showToast(row.kind==='certificate'?'证书已恢复；自动化仍停用，请在证书配置中核对并启用':'凭据已恢复');
});}

function newCredential(row){
 form.value={id:row?.id,name:row?.name||'',kind:row?.kind||'aliyun',secrets:['ssh','yunxiao'].includes(row?.kind)?{...row.summary}: {}};
 modal.value='credential';error.value='';
}
async function saveCredential(){await run(async()=>{await api('/credentials'+(form.value.id?'/'+form.value.id:''),form.value.id?'PATCH':'POST',
 {name:form.value.name,kind:form.value.kind,secrets:form.value.secrets});modalClose();await refresh();showToast('凭据已加密保存');})}
async function fingerprint(){await run(async()=>{const r=await api('/ssh-fingerprint','POST',{host:form.value.secrets.host,port:Number(form.value.secrets.port||22)});
 form.value.secrets.host_key=r.fingerprint;showToast('已获取当前连接的主机指纹，请与可信记录核对后保存');})}
async function testCredential(row){if(row.kind==='feishu'&&!confirm('将向此飞书机器人发送一条测试通知，继续？'))return;
 await run(async()=>showToast((await api('/credentials/'+row.id+'/test','POST',{})).message));}

function newCertificate(row){
 form.value=row?{...clone(row),domainsText:row.domains.join('\n')}: {name:'',domainsText:'',source:'upload',credential_id:null,
 issuer_config:{},auto_renew:false,auto_deploy:false,renew_before_days:30,enabled:true};
 modal.value='certificate';error.value='';
}
function setIssuer(){form.value.issuer_config=clone(form.value.source==='aliyun_v1'?catalog.value.issuer_v1:catalog.value.issuer_v2);if(form.value.source==='upload')form.value.auto_renew=false;}
async function saveCertificate(){await run(async()=>{const f=form.value;const data={name:f.name,domains:f.domainsText.split(/[\s,，]+/).filter(Boolean),
 source:f.source,credential_id:f.credential_id||null,issuer_config:f.issuer_config,auto_renew:f.auto_renew,auto_deploy:f.auto_deploy,
 renew_before_days:Number(f.renew_before_days),enabled:f.enabled};
 const row=await api('/certificates'+(f.id?'/'+f.id:''),f.id?'PATCH':'POST',data);modalClose();await refresh();
 if(!f.id&&f.source==='upload')await upload(row);else showToast('证书配置已保存');})}
async function loadUploadImpact(f=form.value){f.impact_loading=true;f.impact_preview=null;error.value='';try{
 const plan=await api('/certificates/'+f.id+'/update-preview');
 if(modal.value==='upload'&&form.value===f)f.impact_preview=plan;
 }catch(e){if(form.value===f)error.value=e.message}finally{f.impact_loading=false;}}
async function upload(row){form.value={id:row.id,name:row.name,cert_pem:'',key_pem:'',impact_preview:null,impact_loading:true};modal.value='upload';error.value='';await loadUploadImpact();}
async function readFile(event,key){const f=event.target.files[0];if(!f)return;if(f.size>160000){error.value='文件过大';return}form.value[key]=await f.text();}
async function uploadVersion(){if(!form.value.impact_preview)return;await run(async()=>{const count=form.value.impact_preview.automatic_count;
 await api('/certificates/'+form.value.id+'/versions','POST',{cert_pem:form.value.cert_pem,key_pem:form.value.key_pem,impact_token:form.value.impact_preview.preview_token});
 modalClose();await refresh();showToast(count?`新版本已保存；${count} 个自动更新目标校验通过后进入任务队列`:'新版本已保存；当前没有自动更新目标，可预览手动部署');})}
async function history(row){await run(async()=>{form.value={name:row.name,versions:await api('/certificates/'+row.id+'/versions')};modal.value='versions';})}
async function certAction(row,action){if(action==='deploy'){await openDeployment('certificates',row.id);return;}
 if(!confirm(`将使用配置的阿里云证书实例或资源包提交申请。新版本签发后，按当前配置自动更新 ${relationSummary(row.id).automatic} 个目标，继续？`))return;
 await run(async()=>{await api('/certificates/'+row.id+'/'+action,'POST',{});await refresh();showToast('任务已加入队列，可在任务记录查看进度');})}
async function openDeployment(collection,id,action='deploy'){await run(async()=>{
 const plan=await api('/'+collection+'/'+id+'/deploy-preview'+(collection==='targets'?'?action='+action:''));
 form.value={collection,id,action,plan};modal.value='deployment_preview';
});}
async function refreshDeployment(){await run(async()=>{const f=form.value;
 f.plan=await api('/'+f.collection+'/'+f.id+'/deploy-preview'+(f.collection==='targets'?'?action='+f.action:''));
});}
async function submitDeployment(){await run(async()=>{const f=form.value;
 await api('/'+f.collection+'/'+f.id+'/'+f.action,'POST',{preview_token:f.plan.preview_token});
 modalClose();await refresh();showToast('已按确认的目标和证书版本创建任务，可在任务记录查看进度');
});}

function newTarget(row){
 form.value=row?clone(row):{name:'',kind:'dcdn',domain:'',region:'cn-shenzhen',resource_key:'',credential_id:null,
 certificate_id:null,enabled:true,auto_deploy:false,config:{}};
 if(!row)setTargetKind();modal.value='target';error.value='';
}
function setTargetKind(){form.value.config=clone(catalog.value.targets[form.value.kind]?.defaults||{});form.value.credential_id=null;
 if(['ga','dcdn','waf','waf_cloud'].includes(form.value.kind))form.value.region='cn-hangzhou';}
async function saveTarget(){await run(async()=>{const f=form.value;const fields=['name','kind','domain','region','resource_key','credential_id','certificate_id','config','enabled','auto_deploy'];
 const data=Object.fromEntries(fields.map(k=>[k,f[k]]));data.credential_id||=null;data.certificate_id||=null;
 await api('/targets'+(f.id?'/'+f.id:''),f.id?'PATCH':'POST',data);modalClose();await refresh();showToast('部署目标已保存');})}
async function pipelineSetup(row){if(!confirm('将生成新的主机接入凭据，旧凭据会立即失效；生成后需要更新服务器配置。继续？'))return;await run(async()=>{const data=await api('/targets/'+row.id+'/pipeline-token','POST',{});form.value={name:row.name,configuration:JSON.stringify(data.config,null,2)};modal.value='pipeline_setup';})}
async function targetAction(row,action){if(action!=='probe'){await openDeployment('targets',row.id,action);return;}
 await run(async()=>{await api('/targets/'+row.id+'/'+action,'POST',{});await refresh();showToast('任务已加入队列');})}
const associationProducts={DCDN:'全站加速 DCDN',FC:'函数计算 FC',GA:'全球加速 GA',OSS:'对象存储 OSS',SLB:'传统型负载均衡 CLB',WAF:'Web 应用防火墙 WAF'};
const associationCertificates=computed(()=>[...new Map(associations.value.resources.map(r=>[String(r.CertId),{id:String(r.CertId),name:r.CertName||String(r.CertId)}])).values()]);
const certificateAssociations=computed(()=>associations.value.resources.filter(r=>!associationCertificate.value||String(r.CertId)===associationCertificate.value));
const visibleAssociations=computed(()=>certificateAssociations.value.filter(r=>(!productFilter.value||(productFilter.value==='waf_cloud'&&r.CloudProduct==='WAF')||({DCDN:'dcdn',FC:'fc',GA:'ga',OSS:'oss',SLB:'clb',WAF:'waf'}[r.CloudProduct]===productFilter.value))&&`${r.Domain||''} ${r.InstanceId||''} ${r.CertName||''}`.toLowerCase().includes(search.value.toLowerCase())));
function associatedTarget(r){return targets.value.find(t=>{
 if(t.credential_id!==r.credential_id)return false;
 if(r.CloudProduct==='DCDN')return t.kind==='dcdn'&&t.domain===r.Domain;
 if(r.CloudProduct==='FC')return t.kind==='fc'&&t.domain===r.Domain;
 if(r.CloudProduct==='OSS')return t.kind==='oss'&&t.config.bucket===r.InstanceId&&t.domain===r.Domain;
 if(r.CloudProduct==='GA')return t.kind==='ga'&&t.config.listener_id===r.ListenerId&&t.config.cloud_domain===r.Domain;
 if(r.CloudProduct==='SLB')return t.kind==='clb'&&t.config.load_balancer_id===r.InstanceId&&String(t.config.listener_port)===String(r.ListenerPort)&&t.config.cloud_domain===r.Domain;
 if(r.CloudProduct==='WAF')return t.kind==='waf_cloud'&&t.config.resource_instance_id===r.InstanceId&&t.config.cloud_domain===r.Domain;
 return false;
});}
function cloudExpiry(value){if(!value)return '—';const number=Number(value);return date(Number.isFinite(number)?(number<1e12?number*1000:number):value);}
function reviewExclude(row){form.value={id:row.id,name:row.name,domain:row.domain,reason:''};modal.value='exclude';error.value='';}
async function excludeTarget(){await run(async()=>{const f=form.value;
 await api('/targets/'+f.id+'/exclude','POST',{reason:f.reason.trim()||'手动排除'});
 modalClose();await refresh();showToast('目标已排除，后续发现会保留此排除记录');
});}
async function includeTarget(row){await run(async()=>{
 await api('/targets/'+row.id+'/include','POST',{});await refresh();
 showToast('已恢复管理；目标仍停用，请在配置中核对并启用');
});}
function discover(){form.value={credential_id:credentials.value.find(c=>c.kind==='aliyun')?.id||'',regions:['cn-shenzhen','cn-hangzhou'],regionsText:'',products:['dcdn','fc','clb','oss','waf','ga']};modal.value='discover';error.value='';}
async function discoverSubmit(){await run(async()=>{await api('/discover','POST',{credential_id:form.value.credential_id,
 regions:scanRegions.value,products:form.value.products});modalClose();await refresh();showToast('资源发现已排队；新发现的资源不会自动绑定或部署');})}
function cloudInventory(){
 form.value={credential_id:credentials.value.find(c=>c.kind==='aliyun')?.id||'',page:1,inventory:null,cert_id:'',name:'',filter:''};
 modal.value='cloud';error.value='';if(form.value.credential_id)loadCloud();
}
async function loadCloud(requestedPage=1){await run(async()=>{
 const f=form.value;f.inventory=null;f.cert_id='';f.name='';f.filter='';f.page=requestedPage;
 if(!f.credential_id)return;
 const inventory=await api('/cloud/'+f.credential_id+'/certificates?page='+requestedPage);
 if(modal.value==='cloud'&&form.value===f)f.inventory=inventory;
});}
const cloudCertificates=computed(()=>form.value.inventory?.certificates?.CertificateList||[]);
const cloudTotal=computed(()=>form.value.inventory?.certificates?.TotalCount??cloudCertificates.value.length);
const cloudPages=computed(()=>Math.max(1,Math.ceil(cloudTotal.value/(form.value.inventory?.certificates?.ShowSize||100))));
const visibleCloudCertificates=computed(()=>cloudCertificates.value.filter(c=>`${c.CertificateName||''} ${c.Domain||''} ${c.CertificateId}`.toLowerCase().includes((form.value.filter||'').trim().toLowerCase())));
const selectedCloudCertificate=computed(()=>cloudCertificates.value.find(c=>String(c.CertificateId)===form.value.cert_id));
function selectCloudCertificate(c){form.value.cert_id=String(c.CertificateId);form.value.name=(c.CertificateName||c.Domain?.split(',')[0]||`阿里云证书 ${c.CertificateId}`).slice(0,160);}
function cloudDays(c){const expiry=Number(c.NotAfter);return expiry>0?Math.ceil((expiry-Date.now())/86400000):null;}
function cloudStatus(c){const days=cloudDays(c);return days!==null&&days<0?'已过期':({issued:'已签发',willExpire:'即将到期',expired:'已过期',revoked:'已吊销'}[c.CertificateStatus]||c.CertificateStatus||'未知');}
function cloudHasNoKey(c){return [false,0,'false','0'].includes(c.ExistPrivateKey);}
async function importCloud(){if(!selectedCloudCertificate.value){error.value='请先选择要导入的证书';return;}await run(async()=>{
 const row=await api('/cloud/import','POST',{credential_id:form.value.credential_id,cert_id:Number(form.value.cert_id),name:form.value.name.trim()});
 modalClose();await refresh();
 if(row.import_status==='existing'||row.import_status==='key_added'){
  showToast(`证书已存在于「${row.name}」${row.imported_version_is_latest?'':'的历史版本'}，${row.import_status==='key_added'?'已补充并加密保存私钥':'已复用原记录'}`);
 }else showToast(row.latest_version?.has_private_key?'证书和私钥已导入，私钥已加密保存':'证书已导入；云端未提供私钥，当前仅可用于到期监控');
});}
async function retry(job){await run(async()=>{await api('/jobs/'+job.id+'/retry','POST',{});await refresh();showToast('任务已恢复；已提交的部署将继续检查生效结果');})}
function jobDetails(job){form.value=clone(job);modal.value='job';error.value='';}
async function saveNotifications(){await run(async()=>{const data={...notification.value.settings,days:noticeDays.value.split(/[\s,，]+/).filter(Boolean).map(Number)};
 await api('/notifications','PUT',data);await refresh();showToast('通知规则已保存');})}
const filteredCerts=computed(()=>certs.value.filter(c=>`${c.name} ${c.domains.join(' ')}`.toLowerCase().includes(search.value.toLowerCase())));
const filteredTargets=computed(()=>targets.value.filter(t=>(targetVisibility.value==='all'||t.excluded===(targetVisibility.value==='excluded'))&&(!productFilter.value||t.kind===productFilter.value)&&`${t.name} ${t.domain}`.toLowerCase().includes(search.value.toLowerCase())));
const workerHealthy=computed(()=>dashboard.value.worker?.heartbeat&&Date.now()-new Date(dashboard.value.worker.heartbeat).getTime()<180000);
const recentJobs=computed(()=>jobs.value.slice(0,6));
onMounted(async()=>{await boot();timer=setInterval(()=>{if(user.value&&!user.value.must_change&&!modal.value&&!busy.value)refresh().catch(e=>error.value=e.message);},20000);});
onUnmounted(()=>{clearInterval(timer);clearTimeout(toastTimer)});
</script>

<template>
 <div v-if="loading" class="loading">正在连接证书控制台…</div>
 <div v-else-if="!user" class="login-screen">
  <div class="login-art"><div class="shield">✓</div><span class="eyebrow">CERTIFICATE OPERATIONS</span><h1>每个入口，<br>都有有效的证书。</h1><p>统一管理证书版本、云产品与 Nginx，<br>从申请部署到实际生效检查。</p><div class="login-tags"><span>阿里云产品</span><span>跨云 Nginx</span><span>飞书通知</span></div></div>
  <form class="login-card" @submit.prevent="login"><span class="eyebrow">域名证书控制台</span><h2>登录管理控制台</h2><p class="muted">{{authOptions.feishu?'已获本系统授权的成员可使用飞书登录。':'使用管理员账号访问你的证书与部署资源。'}}</p><div v-if="error" class="error" role="alert">{{error}}</div><template v-if="authOptions.feishu"><a class="feishu-login" :href="authOptions.login_url"><span aria-hidden="true">↗</span> 使用飞书登录</a><div class="login-divider">或使用本地管理员账号</div></template><label>账号<input v-model="loginForm.username" autocomplete="username" required></label><label>密码<input v-model="loginForm.password" type="password" autocomplete="current-password" required></label><button :class="['full',{'primary':!authOptions.feishu}]" :disabled="busy">{{busy?'正在登录…':'账号密码登录 →'}}</button><small>本地管理员首次登录后需要设置新密码。</small></form>
 </div>
 <div v-else-if="user.must_change" class="login-screen change-screen"><form class="login-card" @submit.prevent="changePassword"><div class="shield small">✓</div><h2>设置管理员密码</h2><p class="muted">初始密码仅用于首次登录。请设置至少 16 位的新密码。</p><label>当前密码<input v-model="passwordForm.current_password" type="password" autocomplete="current-password" required></label><label>新密码<input v-model="passwordForm.password" type="password" minlength="16" autocomplete="new-password" required></label><div v-if="error" class="error">{{error}}</div><button class="primary full" :disabled="busy">保存并进入控制台</button></form></div>
 <div v-else class="shell">
  <aside class="sidebar"><div class="brand"><span class="brand-mark">✓</span><div>证书控制台<small>CERTIFICATE OPS</small></div></div><div class="nav-label">工作空间</div><nav><button v-for="n in nav" :key="n[0]" :class="{active:page===n[0]}" @click="go(n[0])"><span>{{n[1]}}</span>{{n[2]}}<i v-if="n[0]==='jobs'&&dashboard.pending_jobs">{{dashboard.pending_jobs}}</i></button></nav><div class="sidebar-footer"><span :class="['status-dot',workerHealthy?'online':'offline']"></span>{{workerHealthy?'后台任务运行中':'后台任务待检查'}}<small>北京时间 · 按目标计划巡检</small></div></aside>
  <main><header class="topbar"><span>工作空间 <span class="slash">/</span> {{currentTitle}}</span><div><span class="admin-avatar">{{user.provider==='feishu'?'飞':'A'}}</span>{{user.display_name||user.username}}<button v-if="user.provider!=='feishu'" class="text-button" @click="modal='password';error=''">修改密码</button><button class="text-button" @click="logout">退出</button></div></header>
   <div class="content"><div class="page-heading"><div><span class="eyebrow">CERTIFICATE OPERATIONS</span><h1>{{currentTitle}}</h1><p>{{{overview:'查看证书有效期、目标状态与自动化任务。',certificates:'管理证书来源、历史版本与续签策略。',relations:'按证书查看服务和机器，确认更新范围与实际使用关系。',targets:'将证书绑定到云产品、HTTPS 入口和 Nginx 站点。',credentials:'集中管理已加密保存的云、主机和通知凭据。',jobs:'追踪每一次申请、部署和实际生效检查。',notifications:'设置临期提醒、异常通知与恢复通知。',audit:'查看管理员操作与任务异常记录。',trash:'恢复已删除的证书和访问凭据。证书恢复后需手动启用自动化。'}[page]}}</p></div><div class="heading-actions"><button @click="run(refresh)" :disabled="busy">↻ 刷新</button><button v-if="page==='certificates'" class="primary" @click="newCertificate()">＋ 新建证书</button><button v-if="page==='targets'" class="primary" @click="newTarget()">＋ 添加目标</button><button v-if="page==='credentials'" class="primary" @click="newCredential()">＋ 添加凭据</button></div></div>
   <div v-if="error&&!modal" class="error" role="alert">{{error}}<button class="text-button" @click="error=''">关闭</button></div>
   <template v-if="page==='overview'">
    <div class="stat-grid"><article><span>已管理证书</span><strong>{{dashboard.certificates||0}}</strong><small>最新证书版本</small></article><article><span>30 天内到期</span><strong class="warning">{{dashboard.expiring||0}}</strong><small>需要关注续签进度</small></article><article><span>证书已过期</span><strong :class="dashboard.expired?'danger':''">{{dashboard.expired||0}}</strong><small>证书库中的过期版本</small></article><article><span>部署目标异常</span><strong :class="dashboard.target_issues?'danger':''">{{dashboard.target_issues||0}}</strong><small>实际 TLS 检查或版本不一致</small></article></div>
    <div v-if="!credentials.length" class="onboarding"><div class="onboard-icon">◇</div><div><h3>连接你的第一个证书环境</h3><p>添加访问凭据，然后上传或申请证书，绑定需要更新的部署目标。</p></div><button class="primary" @click="go('credentials');newCredential()">添加访问凭据 →</button></div>
    <div class="overview-grid"><section class="panel"><div class="panel-head"><h3>部署目标分布</h3><span>{{dashboard.targets||0}} 个目标</span></div><div class="product-list"><div v-for="(p,key) in catalog.targets" :key="key"><span class="product-icon">{{key==='nginx'?'N':key.slice(0,1).toUpperCase()}}</span><div>{{p.label}}</div><strong>{{dashboard.products?.[key]||0}}</strong></div></div></section><section class="panel"><div class="panel-head"><h3>自动化运行状态</h3><span :class="['badge',workerHealthy?'good':'bad']">{{workerHealthy?'运行中':'待检查'}}</span></div><div class="automation-summary"><div><span>最近调度心跳</span><strong>{{date(dashboard.worker?.heartbeat)}}</strong></div><div><span>排队 / 等待任务</span><strong>{{dashboard.pending_jobs||0}}</strong></div><div><span>失败任务</span><strong>{{dashboard.failed_jobs||0}}</strong></div><div><span>飞书通知</span><strong>{{dashboard.notifications?.enabled?'已开启':'未开启'}}</strong></div><div><span>通知发送失败</span><strong>{{dashboard.alerts_failed||0}}</strong></div></div><p class="panel-note">证书库版本与目标实际证书分别记录。任务只有通过 TLS 检查才会显示部署完成。</p></section></div>
    <section class="panel"><div class="panel-head"><h3>最近任务</h3><button class="text-button" @click="go('jobs')">查看全部 →</button></div><div v-if="!jobs.length" class="empty compact"><span>↗</span><h3>还没有任务记录</h3><p>添加证书和目标后，申请、部署与巡检结果会显示在这里。</p></div><div v-else class="table-wrap"><table><thead><tr><th>任务类型</th><th>部署目标 / 证书</th><th>状态</th><th>创建时间</th><th></th></tr></thead><tbody><tr v-for="j in recentJobs" :key="j.id"><td>{{kindNames[j.kind]}}</td><td>{{j.target_id?targetName(j.target_id):certName(j.certificate_id)}}</td><td><span :class="['badge',statusClass(j.state)]">{{stateLabel(j.state)}}</span></td><td>{{date(j.created_at)}}</td><td><button class="text-button" @click="jobDetails(j)">详情</button></td></tr></tbody></table></div></section>
   </template>
   <template v-else-if="page==='certificates'">
    <div class="toolbar"><input v-model="search" class="search" placeholder="搜索证书名称或域名"><button @click="cloudInventory">从阿里云导入</button></div><section class="panel"><div v-if="!filteredCerts.length" class="empty"><span>◇</span><h3>{{search?'未找到匹配证书':'还没有管理证书'}}</h3><p>上传已有证书和私钥，或配置阿里云证书实例开始申请。</p><button class="primary" @click="newCertificate()">新建证书</button></div><div v-else class="table-wrap"><table><thead><tr><th>证书 / 域名</th><th>来源</th><th>最新版本有效期</th><th>剩余天数</th><th>更新范围 / 使用关系</th><th>自动化</th><th>操作</th></tr></thead><tbody><tr v-for="c in filteredCerts" :key="c.id"><td><strong>{{c.name}}</strong><small v-for="d in c.domains" :key="d">{{d}}</small><small v-if="!c.enabled" class="danger">已停用</small></td><td>{{c.source==='upload'?'上传证书':c.source==='aliyun_v2'?'阿里云 V2.0':'阿里云 V1.0'}}</td><td>{{c.latest_version?date(c.latest_version.not_after):stateLabel(c.state)}}<small v-if="c.latest_version&&!c.latest_version.has_private_key">仅监控，未保存私钥</small></td><td :class="daysClass(c.latest_version?.days_left)">{{remaining(c.latest_version?.days_left)}}</td><td><button class="text-button" @click="showRelations(c)">手动 {{relationSummary(c.id).manual}} · 自动 {{relationSummary(c.id).automatic}}</button><small>云端关联 {{relationSummary(c.id).cloud}} · 已绑定 {{relationSummary(c.id).bound}}</small></td><td><small>续签 {{c.auto_renew?'开启':'关闭'}}</small><small>部署 {{c.auto_deploy?'开启':'关闭'}}</small></td><td><div class="row-actions"><button @click="showRelations(c)">服务 / 机器</button><button @click="newCertificate(c)">配置</button><button @click="upload(c)">上传版本</button><button @click="history(c)">历史</button><button class="danger" @click="reviewDelete('certificates',c)" :disabled="busy">删除</button><button v-if="c.source!=='upload'" @click="certAction(c,'issue')">申请</button><button :disabled="!relationSummary(c.id).manual" @click="certAction(c,'deploy')">部署</button></div></td></tr></tbody></table></div></section>
   </template>
   <CertificateRelations v-else-if="page==='relations'" :graph="relationGraph" :selected-id="selectedRelation" :busy="busy" @select="selectedRelation=$event" @configure="configureRelationship" @certificate-config="configureRelationCertificate" @deploy="openDeployment('certificates',$event)" />
   <template v-else-if="page==='targets'">
    <div class="toolbar"><input v-model="search" class="search" placeholder="搜索目标名称或域名"><select v-model="targetVisibility" aria-label="目标范围"><option value="managed">管理中（{{targets.filter(t=>!t.excluded).length}}）</option><option value="excluded">已排除（{{targets.filter(t=>t.excluded).length}}）</option><option value="all">全部目标</option><option value="cloud">云端证书关联（{{associations.resources.length}}）</option></select><select v-if="targetVisibility==='cloud'" v-model="associationCertificate" aria-label="关联证书"><option value="">全部证书</option><option v-for="c in associationCertificates" :key="c.id" :value="c.id">{{c.name}}</option></select><select v-model="productFilter"><option value="">全部产品</option><option v-for="(p,k) in catalog.targets" :value="k">{{p.label}}</option></select><button @click="discover">发现阿里云资源</button></div><template v-if="targetVisibility==='cloud'"><div class="info-bar">此处按阿里云 SSL 控制台的证书部署关联展示，保留通配符和默认监听器。可选择一张证书核对各产品数量；点击「配置目标」建立部署绑定。<small v-for="s in associations.snapshots" :key="s.credential_id">{{s.name}} · 最近同步 {{date(s.synced_at)}}</small></div><div class="association-counts"><span v-for="(label,key) in associationProducts" :key="key">{{label}} <strong>{{certificateAssociations.filter(r=>r.CloudProduct===key).length}}</strong></span></div><section class="panel"><div v-if="!visibleAssociations.length" class="empty compact"><h3>暂无匹配的证书关联</h3><p>点击「发现阿里云资源」同步清单，或调整证书和产品筛选。</p></div><div v-else class="table-wrap"><table><thead><tr><th>产品 / 证书覆盖范围</th><th>云资源</th><th>云端证书</th><th>部署目标</th><th>操作</th></tr></thead><tbody><tr v-for="r in visibleAssociations" :key="r.credential_id+r.Id"><td><strong>{{associationProducts[r.CloudProduct]}}</strong><small>{{r.Domain}}</small></td><td><span>{{r.InstanceId||r.Domain}}</span><small>{{r.ListenerId||''}}{{r.ListenerPort?' · 端口 '+r.ListenerPort:''}}</small><small>{{r.RegionId||'全局'}} · {{r.DefaultResource?'默认关联':'扩展关联'}}</small></td><td>{{r.CertName||r.CertId}}<small>到期 {{cloudExpiry(r.CertEndTime)}}</small></td><td>{{associatedTarget(r)?(associatedTarget(r).excluded?'已排除':associatedTarget(r).observed?.configuration_required?'待配置探测域名':'已发现'):'待核对接入配置'}}</td><td><button :disabled="!associatedTarget(r)||associatedTarget(r)?.excluded" @click="newTarget(associatedTarget(r))">配置目标</button></td></tr></tbody></table></div></section></template><section v-else class="panel"><div v-if="!filteredTargets.length" class="empty"><span>▤</span><h3>{{targetVisibility==='excluded'?'暂无匹配的已排除目标':'暂无匹配的部署目标'}}</h3><p>{{targetVisibility==='excluded'?'已排除的目标会保留配置和历史，需要时可恢复管理。':'按自定义域名、HTTPS 监听器和 Nginx 站点分别添加目标。'}}</p><button v-if="targetVisibility!=='excluded'" class="primary" @click="newTarget()">添加部署目标</button></div><div v-else class="table-wrap"><table><thead><tr><th>目标 / 域名</th><th>云产品</th><th>绑定证书</th><th>实际剩余</th><th>TLS 检查</th><th>最近检查</th><th>操作</th></tr></thead><tbody><tr v-for="t in filteredTargets" :key="t.id"><td><strong>{{t.name}}</strong><small>{{t.domain}}</small><small v-if="t.excluded" class="muted">已排除 · {{date(t.excluded_at)}}</small><small v-else-if="t.observed?.configuration_required" class="warning">待配置探测域名</small><small v-else-if="!t.enabled" class="danger">已停用</small><small v-if="t.config.cloud_domain&&t.config.cloud_domain!==t.domain">云端证书范围：{{t.config.cloud_domain}}</small><small v-if="t.excluded" class="target-exclusion-reason">{{t.exclusion_reason}}</small></td><td>{{productLabel(t.kind)}}<small>{{t.region}}</small></td><td><button v-if="t.certificate_id" class="text-button" @click="showRelations({id:t.certificate_id})">{{certName(t.certificate_id)}}</button><span v-else>未绑定</span><small>实际证书：{{actualCertificate(t)}}</small><small>{{t.certificate_id&&relationGraph.certificates.find(c=>c.id===t.certificate_id)?.bindings.some(r=>r.target_id===t.id&&r.automatic_on_new_version)?'新版本自动更新':'不会自动更新'}}</small></td><td :class="daysClass(t.observed?.days_left)">{{remaining(t.observed?.days_left)}}</td><td><span v-if="!t.checked_at" class="badge">待检查</span><span v-else :class="['badge',t.observed?.ok&&t.observed?.version_matches!==false?'good':'bad']">{{t.observed?.ok?(t.observed?.version_matches===false?'版本未同步':'正常'):'异常'}}</span><small class="truncate" :title="t.observed?.error||t.observed?.trust_error">{{t.observed?.error||t.observed?.trust_error}}</small><small v-if="t.observed?.fingerprint">{{short(t.observed.fingerprint)}}</small><small v-if="t.observed?.source==='pipeline_local'">流水线主机本地验证</small></td><td>{{date(t.checked_at)}}</td><td><div class="row-actions"><button v-if="t.excluded" @click="includeTarget(t)" :disabled="busy">恢复管理</button><template v-else><button @click="newTarget(t)">配置</button><button v-if="t.kind==='yunxiao'" @click="pipelineSetup(t)" :disabled="busy">主机接入配置</button><button @click="targetAction(t,'probe')" :disabled="!t.enabled">检查</button><button v-if="t.kind!=='monitor'" :disabled="!t.certificate_id||!t.enabled" @click="targetAction(t,'deploy')">部署</button><button v-if="t.previous_version_id" :disabled="!t.enabled" @click="targetAction(t,'rollback')">回退</button><button class="danger" @click="reviewExclude(t)" :disabled="busy">排除</button></template></div></td></tr></tbody></table></div></section>
   </template>
   <template v-else-if="page==='credentials'">
    <div class="info-bar">凭据和证书私钥加密保存。编辑时留空的密钥字段将保留原值，列表与 API 不返回密钥原文。</div><div v-if="!credentials.length" class="panel empty"><span>⌘</span><h3>添加访问凭据</h3><p>阿里云凭据用于证书申请与云产品部署；SSH 凭据用于跨云 Nginx；飞书凭据用于群通知。</p><button class="primary" @click="newCredential()">添加凭据</button></div><div v-else class="credential-grid"><article v-for="c in credentials" :key="c.id" class="panel credential-card"><div class="credential-top"><span class="credential-icon">{{c.kind==='aliyun'?'A':c.kind==='ssh'?'>_':c.kind==='yunxiao'?'流':'飞'}}</span><span class="badge good">已加密保存</span></div><h3>{{c.name}}</h3><p>{{kindNames[c.kind]}}</p><div class="credential-meta">{{c.kind==='aliyun'?c.summary.access_key_id:c.kind==='ssh'?`${c.summary.username}@${c.summary.host}:${c.summary.port||22}`:c.kind==='yunxiao'?`组织 ${c.summary.organization_id}`:'飞书群机器人 Webhook'}}</div><small v-if="c.kind==='ssh'" class="mono truncate">{{c.summary.host_key}}</small><div class="credential-actions"><button @click="newCredential(c)">编辑凭据</button><button @click="testCredential(c)" :disabled="busy">{{c.kind==='feishu'?'发送测试通知':'测试连接'}}</button><button class="danger" @click="reviewDelete('credentials',c)" :disabled="busy">删除</button></div></article></div>
   </template>
   <template v-else-if="page==='jobs'">
    <section class="panel"><div v-if="!jobs.length" class="empty"><span>↗</span><h3>还没有任务</h3><p>申请、部署、资源发现和每小时巡检都会产生持久化任务记录。</p></div><div v-else class="table-wrap"><table><thead><tr><th>任务类型 / 标识</th><th>目标 / 证书</th><th>状态</th><th>最近结果</th><th>更新时间</th><th>操作</th></tr></thead><tbody><tr v-for="j in jobs" :key="j.id"><td><strong>{{kindNames[j.kind]}}</strong><small class="mono">{{short(j.id)}}</small></td><td>{{j.target_id?targetName(j.target_id):j.certificate_id?certName(j.certificate_id):'云资源发现'}}</td><td><span :class="['badge',statusClass(j.state)]">{{stateLabel(j.state)}}</span><small>{{j.attempts}} 次执行</small></td><td class="job-message">{{j.error||(j.progress?.warnings?.length?'存在发现提示，查看详情':'—')}}</td><td>{{date(j.updated_at)}}</td><td><div class="row-actions"><button @click="jobDetails(j)">详情</button><button v-if="['failed','waiting'].includes(j.state)" @click="retry(j)" :disabled="busy">重试</button></div></td></tr></tbody></table></div></section>
   </template>
   <template v-else-if="page==='notifications'">
    <section class="panel notification-settings"><h3>飞书通知规则</h3><p class="muted">临期提醒每日去重，申请与部署异常及时通知，恢复后发送恢复通知。</p><form @submit.prevent="saveNotifications"><label class="check"><input type="checkbox" v-model="notification.settings.enabled">启用飞书通知</label><label>飞书机器人<select v-model="notification.settings.credential_id"><option :value="null">请选择已保存的飞书凭据</option><option v-for="c in credentials.filter(c=>c.kind==='feishu')" :value="c.id">{{c.name}}</option></select></label><label>到期前提醒天数<input v-model="noticeDays" placeholder="30,15,7,3,1"><small>使用英文逗号分隔；过期后每天提醒。</small></label><button class="primary" :disabled="busy">保存通知规则</button><button type="button" @click="newCredential({kind:'feishu',summary:{}})">添加飞书凭据</button></form></section><section class="panel"><div class="panel-head"><h3>通知记录</h3></div><div v-if="!notification.alerts.length" class="empty compact"><span>♧</span><h3>暂无通知记录</h3><p>配置并启用机器人后，符合规则的通知会显示在这里。</p></div><div v-else class="table-wrap"><table><thead><tr><th>通知</th><th>内容</th><th>状态</th><th>发送时间</th></tr></thead><tbody><tr v-for="a in notification.alerts" :key="a.id"><td>{{a.title}}</td><td class="job-message pre-line">{{a.content}}<small class="danger">{{a.error}}</small></td><td><span :class="['badge',statusClass(a.state)]">{{stateLabel(a.state)}}</span></td><td>{{date(a.sent_at||a.created_at)}}</td></tr></tbody></table></div></section>
   </template>
   <template v-else-if="page==='trash'"><div class="info-bar">删除仅移除本控制台的可用记录，可恢复；历史记录和加密密钥仍保留。不会删除云端证书、吊销云端 AccessKey 或修改服务器文件。</div><section class="panel"><div v-if="!trash.length" class="empty compact"><h3>回收站为空</h3><p>删除的证书和访问凭据会显示在这里。</p></div><div v-else class="table-wrap"><table><thead><tr><th>名称</th><th>类型</th><th>删除时间</th><th>操作者</th><th>操作</th></tr></thead><tbody><tr v-for="r in trash" :key="r.kind+r.resource_id"><td><strong>{{r.name}}</strong><small class="mono">{{short(r.resource_id)}}</small></td><td>{{r.kind==='certificate'?'证书':'访问凭据'}}</td><td>{{date(r.deleted_at)}}</td><td>{{r.deleted_by}}</td><td><button @click="restoreResource(r)" :disabled="busy">恢复</button></td></tr></tbody></table></div></section></template>
   <template v-else-if="page==='audit'"><section class="panel"><div v-if="!audit.length" class="empty compact">暂无审计记录</div><div v-else class="table-wrap"><table><thead><tr><th>时间</th><th>操作者</th><th>操作</th><th>资源</th><th>详情</th></tr></thead><tbody><tr v-for="a in audit" :key="a.id"><td>{{date(a.created_at)}}</td><td>{{a.actor}}</td><td>{{a.action}}</td><td class="mono">{{short(a.resource_id)}}</td><td><code>{{JSON.stringify(a.details)}}</code></td></tr></tbody></table></div></section></template>
   <footer class="page-footer">域名证书控制台 <span>•</span> v1.6.0 <span>•</span> 实际有效期以目标 TLS 检查为准</footer></div>
  </main>
 </div>
 <div v-if="toast" class="toast" role="status">✓ {{toast}}</div>
 <div v-if="modal&&user&&!user.must_change" class="modal-backdrop" @click.self="modalClose"><section :class="['modal',{'cloud-modal':modal==='cloud','deployment-modal':modal==='deployment_preview'}]" role="dialog" aria-modal="true" :aria-label="modal==='cloud'?'从阿里云导入证书':undefined"><header><h2>{{{credential:form.id?'编辑凭据':'添加访问凭据',certificate:form.id?'配置证书':'新建证书',upload:'上传证书版本',versions:'证书历史版本',target:form.id?'配置部署目标':'添加部署目标',discover:'发现阿里云资源',cloud:'从阿里云导入证书',pipeline_setup:'主机接入配置',job:'任务详情',password:'修改管理员密码',delete:'删除记录',exclude:'排除部署目标',deployment_preview:form.action==='rollback'?'确认回退影响范围':'确认部署影响范围'}[modal]}}</h2><button class="close" aria-label="关闭" @click="modalClose">×</button></header><div class="modal-body"><div v-if="error" class="error" role="alert">{{error}}</div>
  <DeploymentPreview v-if="modal==='deployment_preview'" :plan="form.plan" :busy="busy" :rollback="form.action==='rollback'" @confirm="submitDeployment" @refresh="refreshDeployment" @cancel="modalClose" />
  <div v-else-if="modal==='delete'"><p>将 <strong>{{form.name}}</strong> 移入回收站？</p><p class="hint">可从回收站恢复，历史记录和加密密钥仍保留。不会删除云端证书、吊销云端 AccessKey 或修改服务器文件。</p><p v-if="form.collection==='certificates'" class="hint">删除后停止此证书的续签、自动部署及到期提醒；恢复后需手动启用。</p><template v-if="!form.can_delete"><div class="error">此记录仍被引用，暂不能删除。请先处理以下记录：</div><ul class="delete-blockers"><li v-for="b in form.blockers" :key="b.kind+b.id"><strong>{{b.name}}</strong><span>{{b.reason}}</span></li></ul></template><div class="form-actions"><button @click="modalClose">取消</button><button class="danger-button" @click="deleteResource" :disabled="busy||!form.can_delete">移入回收站</button></div></div>
  <form v-else-if="modal==='exclude'" @submit.prevent="excludeTarget"><p>将 <strong>{{form.name}}</strong> 排除出证书管理？</p><p class="hint">{{form.domain}}</p><p class="hint">停止此目标的巡检、部署和到期提醒，保留配置和历史记录。后续资源发现不会重新加入管理中列表；可在「已排除」列表恢复，恢复后需核对并启用目标。</p><label>排除原因（可选）<textarea v-model="form.reason" rows="3" maxlength="400" placeholder="例如：阿里云平台原生域名，与业务证书无关"></textarea></label><div class="form-actions"><button type="button" @click="modalClose">取消</button><button class="danger-button" :disabled="busy">确认排除</button></div></form>
  <form v-else-if="modal==='credential'" @submit.prevent="saveCredential"><label>凭据名称<input v-model="form.name" required placeholder="例如：阿里云生产账号"></label><label>凭据类型<select v-model="form.kind" :disabled="!!form.id" @change="form.secrets={}"><option value="aliyun">阿里云 AccessKey</option><option value="ssh">SSH 主机 / 跳板机</option><option value="feishu">飞书 Webhook</option><option value="yunxiao">云效个人访问令牌</option></select></label><p v-if="form.id" class="hint">密钥字段留空时保留原值。</p>
   <template v-if="form.kind==='aliyun'"><label>AccessKey ID<input v-model="form.secrets.access_key_id" autocomplete="off" :required="!form.id"></label><label>AccessKey Secret<input v-model="form.secrets.access_key_secret" type="password" autocomplete="new-password" :required="!form.id"></label><label>临时安全令牌（STS，可选）<input v-model="form.secrets.security_token" type="password" autocomplete="off"></label><label>账号 UID（FC 2.0 使用）<input v-model="form.secrets.account_id"></label><p class="hint">使用专用 RAM 用户或角色，按实际需要授予证书管理、目标产品和 DNS 权限。STS 到期后需要更新。</p></template>
   <template v-if="form.kind==='ssh'"><div class="form-grid"><label>主机地址<input v-model="form.secrets.host" required></label><label>端口<input v-model="form.secrets.port" type="number" min="1" max="65535" placeholder="22"></label></div><label>登录用户<input v-model="form.secrets.username" required placeholder="root"></label><label>SSH 私钥<textarea v-model="form.secrets.private_key" class="mono" rows="5" :required="!form.id" placeholder="粘贴完整 SSH 私钥（PEM / OpenSSH 格式）"></textarea><input type="file" @change="readFile($event,'ssh_key') ; $event.target.files[0]?.text().then(t=>form.secrets.private_key=t)"></label><label>私钥口令（可选）<input v-model="form.secrets.passphrase" type="password" autocomplete="new-password"></label><label>主机 SHA256 指纹<div class="inline-form"><input v-model="form.secrets.host_key" required placeholder="SHA256:…"><button type="button" @click="fingerprint" :disabled="busy||!form.secrets.host">获取指纹</button></div><small>请与可信的 SSH 记录核对；指纹变化时连接会被拒绝。</small></label><label>通过跳板机（可选）<select v-model="form.secrets.jump_credential_id"><option value="">直接连接</option><option v-for="c in credentials.filter(c=>c.kind==='ssh'&&c.id!==form.id)" :value="c.id">{{c.name}}</option></select></label></template>
   <template v-if="form.kind==='yunxiao'"><label>组织 ID<input v-model="form.secrets.organization_id" required placeholder="example-organization"></label><label>个人访问令牌<input v-model="form.secrets.token" type="password" autocomplete="new-password" :required="!form.id"></label><label>测试读取的流水线 ID<input v-model="form.secrets.test_pipeline_id" placeholder="1000001"></label><p class="hint">用于触发流水线及查询运行状态。请配置流水线运行实例的读写权限和流水线只读权限，令牌加密保存。测试连接只读取指定流水线。</p></template><template v-if="form.kind==='feishu'"><label>机器人 Webhook<input v-model="form.secrets.webhook" type="password" autocomplete="new-password" :required="!form.id" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/…"></label><label>签名密钥（机器人开启签名时填写）<input v-model="form.secrets.sign_secret" type="password" autocomplete="new-password"></label></template><div class="form-actions"><button type="button" @click="modalClose">取消</button><button class="primary" :disabled="busy">加密保存</button></div>
  </form>
  <form v-else-if="modal==='certificate'" @submit.prevent="saveCertificate"><label>证书名称<input v-model="form.name" required></label><label>证书来源<select v-model="form.source" @change="setIssuer"><option value="upload">上传已有证书</option><option value="aliyun_v2">阿里云 SSL V2.0 订阅实例</option><option value="aliyun_v1">阿里云 SSL V1.0 证书资源包</option></select></label><label>域名<textarea v-model="form.domainsText" rows="3" :required="form.source!=='upload'" placeholder="api.example.com&#10;*.example.com"></textarea><small>每行一个域名；上传证书后将从证书中自动解析域名。</small></label><template v-if="form.source!=='upload'"><label>阿里云凭据<select v-model="form.credential_id" required><option :value="null">请选择凭据</option><option v-for="c in credentials.filter(c=>c.kind==='aliyun')" :value="c.id">{{c.name}}</option></select></label><template v-if="form.source==='aliyun_v2'"><label>证书订阅实例 ID<input v-model="form.issuer_config.instance_id" required placeholder="cas_dv-cn-…"></label><label>联系人 ID（多个用逗号分隔）<input :value="(form.issuer_config.contact_ids||[]).join(',')" @input="form.issuer_config.contact_ids=$event.target.value.split(',').map(s=>s.trim()).filter(Boolean)"><small>已在阿里云实例中配置联系人的可以留空。</small></label><p class="hint">需要已有订阅实例；本系统不会自动购买或开启付费续费。</p></template><template v-else><label>证书规格 ProductCode<input v-model="form.issuer_config.product_code" required placeholder="digicert-free-1-free"></label><div class="form-grid"><label>联系人<input v-model="form.issuer_config.contact_name" required></label><label>手机号<input v-model="form.issuer_config.phone" required></label></div><label>邮箱<input v-model="form.issuer_config.email" type="email" required></label><label>已有申请订单 ID（恢复申请时填写）<input v-model="form.issuer_config.order_id"></label><label class="check"><input v-model="form.issuer_config.allow_resource_consumption" type="checkbox">允许使用已有证书资源包额度提交申请</label><p class="hint">免费版通常为 90 天单域名证书，受年度额度与域名规则限制。</p></template><label class="check"><input v-model="form.issuer_config.auto_dns" type="checkbox">通过阿里云 DNS API 自动添加验证记录</label><label v-if="form.issuer_config.auto_dns">DNS 凭据<select v-model="form.issuer_config.dns_credential_id"><option value="">使用证书申请凭据</option><option v-for="c in credentials.filter(c=>c.kind==='aliyun')" :value="c.id">{{c.name}}</option></select></label><label class="check"><input v-model="form.auto_renew" type="checkbox">开启自动续签</label><label v-if="form.auto_renew">提前检查续签的天数<input v-model="form.renew_before_days" type="number" min="1" max="120"><small>进入阿里云允许的申请窗口后执行；申请失败会留存任务和告警。</small></label></template><label class="check"><input v-model="form.auto_deploy" type="checkbox">新版本自动部署到已开启自动部署的绑定目标</label><label class="check"><input v-model="form.enabled" type="checkbox">启用此证书的自动化和到期提醒</label><div class="form-actions"><button type="button" @click="modalClose">取消</button><button class="primary" :disabled="busy">保存证书配置</button></div></form>
  <form v-else-if="modal==='upload'" @submit.prevent="uploadVersion"><p class="hint">{{form.name}} · 上传后保留历史版本和已有绑定。请按叶证书、中间证书的顺序提供完整证书链。</p><div class="upload-impact"><div class="relationship-title"><h3>保存新版本后的更新范围</h3><button type="button" :disabled="busy||form.impact_loading" @click="loadUploadImpact()">刷新影响范围</button></div><p v-if="form.impact_loading" role="status">正在读取部署绑定…</p><template v-else-if="form.impact_preview"><p v-if="form.impact_preview.automatic_count">按当前配置，新版本校验通过后将自动更新 <strong>{{form.impact_preview.automatic_count}}</strong> 个目标：</p><p v-else>当前自动更新范围为 <strong>0</strong>。保存新版本后，需要在「证书与服务」预览并手动部署。</p><article v-for="t in form.impact_preview.automatic_targets" :key="t.id"><strong>{{t.name}}</strong><small>{{t.domain}}</small><ServiceDestination :destination="t.destination" /></article><small class="muted">以下上传动作只会按已确认的绑定配置处理。绑定或自动部署设置变化时，请刷新此范围后再保存。</small></template></div><label>PEM 证书链<textarea v-model="form.cert_pem" class="mono" rows="7" required placeholder="-----BEGIN CERTIFICATE-----"></textarea><input type="file" accept=".pem,.crt,.cer,.txt" @change="readFile($event,'cert_pem')"></label><label>PEM 私钥<textarea v-model="form.key_pem" class="mono" rows="5" placeholder="-----BEGIN PRIVATE KEY-----"></textarea><input type="file" accept=".pem,.key,.txt" @change="readFile($event,'key_pem')"><small>私钥可留空用于仅监控；部署时必须有匹配的私钥。</small></label><div class="form-actions"><button type="button" @click="modalClose">取消</button><button class="primary" :disabled="busy||form.impact_loading||!form.impact_preview">校验并保存新版本</button></div></form>
  <div v-else-if="modal==='versions'"><p class="hint">{{form.name}} · 私钥不会在界面返回。</p><div v-if="!form.versions.length" class="empty compact">暂无证书版本</div><article v-for="v in form.versions" class="version-card"><strong :class="daysClass(v.days_left)">{{remaining(v.days_left)}}</strong><p>{{v.domains.join('、')}}</p><small>有效期：{{date(v.not_before)}} 至 {{date(v.not_after)}}</small><small>SHA256：<code>{{v.fingerprint}}</code></small><small>私钥：{{v.has_private_key?'已加密保存':'未提供'}} · 保存时间：{{date(v.created_at)}}</small></article></div>
  <form v-else-if="modal==='target'" @submit.prevent="saveTarget"><label>目标名称<input v-model="form.name" required placeholder="例如：生产 API / WAF"></label><div class="form-grid"><label>产品类型<select v-model="form.kind" :disabled="!!form.id" @change="setTargetKind"><option v-for="(p,k) in catalog.targets" :value="k">{{p.label}}</option></select></label><label>地域<input v-model="form.region" required placeholder="cn-shenzhen"></label></div><p v-if="form.config.cloud_domain" class="hint">云端证书范围：{{form.config.cloud_domain}}。下方填写具体业务域名用于 TLS 检查；新证书须同时覆盖 {{(form.config.required_domains||[]).join('、')}}。</p><p v-if="form.observed?.configuration_required" class="hint">此资源已发现，请填写具体业务域名和探测地址，核对配置后勾选「启用此目标」。</p><label>具体域名 / TLS SNI<input v-model="form.domain" required placeholder="api.example.com"></label><label v-if="catalog.targets[form.kind]?.credential">访问凭据<select v-model="form.credential_id" required><option :value="null">请选择凭据</option><option v-for="c in credentials.filter(c=>c.kind===catalog.targets[form.kind]?.credential)" :value="c.id">{{c.name}}</option></select></label><label>绑定证书<select v-model="form.certificate_id"><option :value="null">暂不绑定（仅监控）</option><option v-for="c in certs" :value="c.id">{{c.name}} · {{c.domains.join('、')}}</option></select><small v-if="selectedBinding">覆盖域名：{{selectedBinding.latest_version?.domains.join('、')||selectedBinding.domains.join('、')}} · 到期：{{date(selectedBinding.latest_version?.not_after)}}</small><small>切换绑定后保存，再点击此目标的「部署」触发更新。目标域名始终填写具体域名；证书文件名可沿用原路径。</small></label><label v-for="(_,k) in catalog.targets[form.kind]?.defaults" :key="k">{{labels[k]||k}}<select v-if="k==='certificate_role'" v-model="form.config[k]"><option value="default">默认证书</option><option value="additional">扩展证书 / SNI</option></select><input v-else v-model="form.config[k]" :type="['listener_port','check_interval_hours'].includes(k)?'number':'text'" :required="catalog.targets[form.kind].required.includes(k)"></label><p v-if="form.kind==='fc'" class="hint">FC 3.0 使用 2023-03-30；FC 2.0 使用 2021-04-06，并在凭据中填写 UID。先完成自定义域名 HTTPS 配置。</p><p v-if="form.kind==='waf'" class="hint">WAF CNAME 接入使用 3.0 或 2.0 接口；云产品接入请单独选择 WAF 3.0 云产品接入。</p><p v-if="form.kind==='yunxiao'" class="hint">云效通过主机组执行指定版本的证书部署，并回传本机 TLS 验证结果。主机唯一标识应填写物理机标识；VIP 不应重复登记为另一台主机。保存目标后配置主机接入凭据及一次性执行脚本。</p><p v-if="form.kind==='nginx'" class="hint">更新已有 Nginx 证书文件，检查配置后重载。容器 Nginx 请填写相应的 docker exec 检查和重载命令。</p><details open><summary>实际生效检查</summary><div class="form-grid"><label>探测地址<input v-model="form.config.probe_address" placeholder="默认使用域名，可填源站 IP"></label><label>TLS 端口<input v-model.number="form.config.probe_port" type="number" min="1" max="65535" placeholder="443"></label></div><label>业务健康检查 URL（可选）<input v-model="form.config.health_url" type="url" placeholder="https://api.example.com/healthz"></label><label>内部 CA 证书（可选）<textarea v-model="form.config.ca_pem" rows="3" placeholder="仅内部 CA 签发的源站需要填写 PEM 根证书"></textarea></label><p class="hint">经过 DCDN、WAF 的源站请填写源站地址。探测使用上方域名作为 SNI，并校验证书信任链。</p></details><label class="check"><input type="checkbox" v-model="form.auto_deploy" :disabled="form.kind==='monitor'">证书新版本自动部署到此目标</label><label class="check"><input type="checkbox" v-model="form.enabled">启用此目标</label><div class="form-actions"><button type="button" @click="modalClose">取消</button><button class="primary" :disabled="busy">保存部署目标</button></div></form>
  <form v-else-if="modal==='discover'" @submit.prevent="discoverSubmit"><p class="hint">只读发现资源，新增目标默认不绑定证书、不启用自动部署。请在任务详情查看未发现资源的原因。</p><label>阿里云凭据<select v-model="form.credential_id" required><option value="">请选择凭据</option><option v-for="c in credentials.filter(c=>c.kind==='aliyun')" :value="c.id">{{c.name}}</option></select></label><fieldset class="discovery-regions"><legend>扫描地域（可多选）</legend><div class="checkbox-grid"><label v-for="r in discoveryRegions" :key="r.id" class="check"><input type="checkbox" :value="r.id" v-model="form.regions">{{r.label}}<span class="muted">{{r.id}}</span></label></div><p v-if="!scanRegions.length" class="danger">请至少选择或填写一个扫描地域。</p></fieldset><label>其他地域（可选）<input v-model="form.regionsText" placeholder="例如：cn-shanghai, ap-southeast-1"><small>输入地域 ID，多个用逗号或空格分隔；会与上方勾选的地域合并去重。DCDN 按账号查询全局资源。</small></label><div class="checkbox-grid"><label v-for="k in ['dcdn','fc','clb','oss','waf','ga']" class="check"><input type="checkbox" :value="k" v-model="form.products">{{productLabel(k)}}</label></div><p class="hint">会同步云端证书关联，并查询默认监听器、通配符及 WAF 云产品接入。无法从 DNS 确认探测域名的资源会保持停用，待配置后启用。</p><div class="form-actions"><button type="button" @click="modalClose">取消</button><button class="primary" :disabled="busy||!scanRegions.length||!form.products.length">开始发现资源</button></div></form>
  <div v-else-if="modal==='cloud'" class="cloud-import">
   <p class="hint">选择一张证书，确认本地名称后点击导入。导入后可查看到期时间，再到「部署目标」绑定需要更新证书的资源。</p>
   <div class="inline-form"><select v-model="form.credential_id" aria-label="阿里云访问凭据" :disabled="busy" @change="loadCloud()"><option value="">请选择阿里云凭据</option><option v-for="c in credentials.filter(c=>c.kind==='aliyun')" :key="c.id" :value="c.id">{{c.name}}</option></select><button @click="loadCloud()" :disabled="busy||!form.credential_id">{{busy&&!form.inventory?'正在查询…':'刷新列表'}}</button></div>
   <p v-if="!form.credential_id" class="cloud-message">请先在「访问凭据」添加阿里云 AccessKey，再选择凭据查询证书。</p>
   <p v-else-if="busy&&!form.inventory" class="cloud-message" role="status">正在读取阿里云证书列表…</p>
   <template v-if="form.inventory">
    <div class="cloud-list-toolbar"><span>共 {{cloudTotal}} 张证书 · 本页 {{cloudCertificates.length}} 张</span><input v-model="form.filter" type="search" aria-label="筛选云端证书" placeholder="搜索名称、域名或证书编号" :disabled="busy"></div>
    <div v-if="!visibleCloudCertificates.length" class="empty compact"><h3>{{cloudCertificates.length?'未找到匹配证书':'暂无可导入的证书'}}</h3><p>{{cloudCertificates.length?'试试其他名称或域名。':'此凭据下没有已签发的证书，可切换凭据，或在证书管理中新建证书申请。'}}</p></div>
    <div v-else class="table-wrap cloud-table"><table><caption class="sr-only">阿里云证书列表，请选择一张证书导入</caption><thead><tr><th>选择</th><th>证书 / 域名</th><th>到期时间</th><th>状态 / 来源</th></tr></thead><tbody><tr v-for="c in visibleCloudCertificates" :key="c.CertificateId" :class="{'cloud-selected':form.cert_id===String(c.CertificateId)}" @click="!busy&&selectCloudCertificate(c)"><td><input type="radio" name="cloud-certificate" :aria-label="`选择 ${c.CertificateName||c.Domain}（${c.CertificateId}）`" :checked="form.cert_id===String(c.CertificateId)" :disabled="busy" @click.stop @change="selectCloudCertificate(c)"></td><td class="cloud-cert-name"><strong>{{c.CertificateName||'未命名证书'}}</strong><small class="cloud-domain">{{(c.Domain||'未提供域名').split(',').join(' · ')}}</small><small class="muted">证书编号 {{c.CertificateId}}<span v-if="cloudHasNoKey(c)"> · 云端无私钥</span></small></td><td><span>{{c.NotAfter?date(Number(c.NotAfter)):'未提供'}}</span><small :class="daysClass(cloudDays(c))">{{cloudDays(c)===null?'':remaining(cloudDays(c))}}</small></td><td><span :class="['badge',cloudStatus(c)==='已过期'||c.CertificateStatus==='revoked'?'bad':c.CertificateStatus==='willExpire'?'warn':'good']">{{cloudStatus(c)}}</span><small class="muted">{{{BUY:'购买证书',TEST:'免费证书',UPLOAD:'上传证书'}[c.CertificateSource]||c.CertificateSource||'—'}}</small></td></tr></tbody></table></div>
    <div v-if="cloudPages>1" class="cloud-pagination"><span>第 {{form.page}} / {{cloudPages}} 页</span><button :disabled="busy||form.page<=1" @click="loadCloud(form.page-1)">上一页</button><button :disabled="busy||form.page>=cloudPages||form.page>=1000" @click="loadCloud(form.page+1)">下一页</button></div>
   </template>
   <form class="cloud-import-form" @submit.prevent="importCloud">
    <div v-if="selectedCloudCertificate" class="cloud-selection" role="status"><strong>已选择：{{selectedCloudCertificate.CertificateName||selectedCloudCertificate.Domain}}</strong><small>证书编号 {{form.cert_id}}，已自动填写，无需手动输入。</small><small v-if="cloudHasNoKey(selectedCloudCertificate)" class="warning">云端未保存私钥，导入后仅用于到期监控；部署前需要上传匹配的私钥。</small></div>
    <p v-else class="cloud-message">请在上方列表选择一张要导入的证书。</p>
    <label>本地证书名称<input v-model="form.name" required maxlength="160" :disabled="!selectedCloudCertificate||busy" placeholder="选择证书后自动填写，可修改"></label>
    <div class="cloud-import-footer"><small>相同证书自动复用已有记录。点击导入时读取证书和私钥，私钥加密保存。</small><button class="primary" :disabled="busy||!selectedCloudCertificate||!form.name.trim()">{{busy&&selectedCloudCertificate?'正在导入…':'导入所选证书'}}</button></div>
   </form>
  </div>
  <div v-else-if="modal==='pipeline_setup'"><p class="hint">{{form.name}} · 配置含本机专用凭据，仅本次显示。保存到服务器 /etc/certops/pipeline.json，所有者为 root，权限为 600。</p><textarea :value="form.configuration" readonly rows="14" aria-label="主机接入配置" spellcheck="false"></textarea><p><a href="/api/pipeline/client.py" download="certops-pipeline.py">下载主机执行脚本</a>，安装到 /usr/local/libexec/certops-pipeline.py，所有者 root、权限 750。</p><p class="hint">在云效主机部署步骤中调用此脚本，由控制台传入任务标识。它只执行本次绑定的证书更新或 TLS 检查。</p><div class="form-actions"><button class="primary" @click="modalClose">已保存并关闭</button></div></div>
  <div v-else-if="modal==='job'"><div class="job-detail-title"><span :class="['badge',statusClass(form.state)]">{{stateLabel(form.state)}}</span><strong>{{kindNames[form.kind]}}</strong></div><dl><dt>任务 ID</dt><dd class="mono">{{form.id}}</dd><dt>创建时间</dt><dd>{{date(form.created_at)}}</dd><dt>更新时间</dt><dd>{{date(form.updated_at)}}</dd><dt>最近结果</dt><dd>{{form.error||'—'}}</dd></dl><h3>执行进度</h3><pre class="json-preview">{{JSON.stringify(form.progress,null,2)}}</pre><p v-if="form.progress?.validation_records?.length" class="hint">请按上面的 validation_records 完成域名验证，或为证书开启自动 DNS 验证。</p><button v-if="['failed','waiting'].includes(form.state)" class="primary" @click="retry(form);modalClose()">重试 / 立即检查</button></div>
  <form v-else-if="modal==='password'" @submit.prevent="changePassword"><label>当前密码<input v-model="passwordForm.current_password" type="password" autocomplete="current-password" required></label><label>新密码（至少 16 位）<input v-model="passwordForm.password" type="password" minlength="16" autocomplete="new-password" required></label><button class="primary" :disabled="busy">更新密码</button></form>
 </div></section></div>
</template>
