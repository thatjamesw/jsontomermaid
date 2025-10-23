
from __future__ import annotations
from typing import Any, Dict, List, Tuple, Union
import re

# ---------- helpers ----------

def _sid(s: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", str(s or "x"))

def _esc(s: Any) -> str:
    if s is None:
        return ""
    return (str(s)
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("{", "\\{")
            .replace("}", "\\}")
            .replace("|", "\\|")
            .replace('"', '\\"'))

def _last(seg_id: str) -> str:
    parts = [p for p in str(seg_id or "").split("/") if p]
    return parts[-1] if parts else ""

def _get(obj: Dict[str, Any], path: str, default=None):
    cur = obj
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

def _split_arm_id(arm_id: str) -> Dict[str, str]:
    out = {"subscription": "", "resourceGroup": "", "provider": "", "type": "", "name": "", "vnet": "", "subnet": ""}
    if not arm_id or "/providers/" not in arm_id.lower():
        return out
    parts = [p for p in arm_id.split("/") if p]
    for i, p in enumerate(parts):
        low = p.lower()
        if low == "subscriptions" and i + 1 < len(parts): out["subscription"] = parts[i+1]
        elif low == "resourcegroups" and i + 1 < len(parts): out["resourceGroup"] = parts[i+1]
        elif low == "providers" and i + 1 < len(parts): out["provider"] = parts[i+1]
    try:
        # find 'providers' case-insensitive
        pi = next(i for i, p in enumerate(parts) if p.lower() == "providers")
        if pi + 2 < len(parts): out["type"] = parts[pi+2]
        if pi + 3 < len(parts): out["name"] = parts[pi+3]
        for j in range(pi+3, len(parts)-1):
            if parts[j].lower() == "virtualnetworks":
                out["vnet"] = parts[j+1]
            if parts[j].lower() == "subnets":
                out["subnet"] = parts[j+1]
    except StopIteration:
        pass
    return out

# ---- generic ARM-id discovery ----
# Strict: capture exactly .../providers/{prov}/{type}/{name} (stop before subresource segments)
ARM_ID_RE = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/[^/]+/[^/]+",
    re.IGNORECASE,
)

def iter_arm_ids(obj, path=""):
    """
    Yield (json_path, arm_id_str) for string values that look like full ARM IDs.
    Only keys named 'id' or ending with 'Id' are considered.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{path}.{k}" if path else k
            if isinstance(v, str) and (k.lower() == "id" or k.lower().endswith("id")):
                m = ARM_ID_RE.search(v)
                if m:
                    yield kp, m.group(0)
            else:
                yield from iter_arm_ids(v, kp)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_arm_ids(v, f"{path}[{i}]")

TYPE_KIND_MAP = {
    "microsoft.network/virtualnetworks": ("vnet", "vnet"),
    "microsoft.network/subnets": ("subnet", "subnet"),
    "microsoft.network/networksecuritygroups": ("nsg", "nsg"),
    "microsoft.network/publicipaddresses": ("pip", "ip"),
    "microsoft.network/publicipprefixes": ("piprefix", "ip"),
    "microsoft.network/networkinterfaces": ("nic", "nic"),
    "microsoft.compute/virtualmachines": ("vm", "vm"),
    "microsoft.compute/disks": ("disk", "disk"),  # align fallback with explicit OS disk node
    "microsoft.network/loadbalancers": ("lb", "lb"),
    "microsoft.network/applicationgateways": ("agw", "agw"),
    "microsoft.network/natgateways": ("nat", "nat"),
    "microsoft.network/routetables": ("rt", "rtbl"),
    "microsoft.network/azurefirewalls": ("fw", "fw"),
    "microsoft.network/virtualnetworkgateways": ("vgw", "vgw"),
    "microsoft.network/localnetworkgateways": ("lngw", "vgw"),
    "microsoft.network/bastionhosts": ("bast", "bastion"),
    "microsoft.network/privatednszones": ("dns", "dns"),
    "microsoft.network/privatednszones/virtualnetworklinks": ("pdnslink", "dns"),
    "microsoft.network/privateendpoints": ("pe", "ip"),
    "microsoft.storage/storageaccounts": ("sa", "store"),
    "microsoft.keyvault/vaults": ("kv", "kv"),
    "microsoft.web/hostingenvironments": ("ase", "ase"),
    "microsoft.web/serverfarms": ("svc", "svc"),
    "microsoft.web/sites": ("svc", "svc"),
    "microsoft.web/staticsites": ("svc", "svc"),
    "microsoft.web/connectiongateways": ("cgw", "cgw"),
}

def resolve_node_id_and_class(rtype: str, name: str) -> tuple[str, str]:
    key = (rtype or "").lower()
    prefix, klass = TYPE_KIND_MAP.get(key, ("node", "svc"))
    return f"{prefix}_{_sid(name)}", klass

def default_label_for_type(rtype: str, name: str) -> str:
    return f"{_esc(rtype)}<br/>{_esc(name)}" if rtype else _esc(name)

# ---------- renderer ----------

def to_mermaid(data: Union[Dict[str, Any], List[Any]], direction: str = "LR", use_styles: bool = False) -> str:
    # Specialized path for Application Gateway
    try:
        if isinstance(data, dict) and str(data.get('type','')).lower() == 'microsoft.network/applicationgateways':
            return render_app_gateway(data, direction=direction, use_styles=use_styles)
        elif isinstance(data, list):
            for _it in data:
                if isinstance(_it, dict) and str(_it.get('type','')).lower() == 'microsoft.network/applicationgateways':
                    return render_app_gateway(_it, direction=direction, use_styles=use_styles)
    except Exception:
        pass

    # App Gateway specialized rendering (single object or first in list)
    try:
        if isinstance(data, dict) and str(data.get('type','')).lower() == 'microsoft.network/applicationgateways':
            return render_app_gateway(data, direction=direction, use_styles=use_styles)
        elif isinstance(data, list):
            for _item in data:
                if isinstance(_item, dict) and str(_item.get('type','')).lower() == 'microsoft.network/applicationgateways':
                    return render_app_gateway(_item, direction=direction, use_styles=use_styles)
    except Exception:
        pass

    dir_token = "LR" if str(direction).upper() == "LR" else "TB"
    br = "<br/>"

    # normalize input
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = [x for x in data if isinstance(x, dict)]
    else:
        raise ValueError("Payload must be an object or an array of objects")

    # group by subscription/resourceGroup
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for r in items:
        sub_id = r.get("subscriptionId") or _split_arm_id(r.get("id","")).get("subscription") or "unknown_sub"
        rg     = r.get("resourceGroup") or _split_arm_id(r.get("id","")).get("resourceGroup") or "unknown_rg"
        grouped.setdefault(sub_id, {}).setdefault(rg, []).append(r)

    lines: List[str] = []
    add = lines.append

    # header + (optional) classes
    add(f"flowchart {dir_token}")
    if use_styles:
        add("classDef default fill:#f7f7f7,stroke:#9e9e9e,color:#333,stroke-width:1px;")
        add("classDef vm fill:#ffffff,stroke:#9e9e9e,color:#111,stroke-width:1.5px;")
        add("classDef nic fill:#fafafa,stroke:#bdbdbd,color:#333;")
        add("classDef disk fill:#fafafa,stroke:#bdbdbd,color:#333;")
        add("classDef vnet fill:#eef6ff,stroke:#90b4ff,color:#0e1b4d;")
        add("classDef subnet fill:#f2f7ff,stroke:#bdd0ff,color:#0e1b4d;")
        add("classDef nsg fill:#fff7e6,stroke:#e0c37a,color:#7a500;")
        add("classDef ip fill:#f0f0f0,stroke:#c7c7c7,color:#333;")
        add("classDef lb fill:#f0fff4,stroke:#58a55c,color:#0a3d14;")
        add("classDef agw fill:#f3f8ff,stroke:#89a7ff,color:#0e1b4d;")
        add("classDef nat fill:#fffaf0,stroke:#e6c37a,color:#6b4e00;")
        add("classDef rtbl fill:#f8f8ff,stroke:#b0b0ff,color:#24245a;")
        add("classDef fw fill:#fff0f0,stroke:#ff8a8a,color:#7a0b0b;")
        add("classDef vgw fill:#f0fffe,stroke:#65d1c6,color:#074b45;")
        add("classDef bastion fill:#f7f0ff,stroke:#c6a0ff,color:#3f1f7a;")
        add("classDef dns fill:#f0f7ff,stroke:#9ac6ff,color:#0e1b4d;")
        add("classDef ase fill:#fff0f6,stroke:#f59ac0,color:#5e1030;")
        add("classDef store fill:#f5fff2,stroke:#a6d07a,color:#244d0a;")
        add("classDef kv fill:#fafff8,stroke:#9ad8a6,color:#0a4d2c;")
        add("classDef svc fill:#f9f9f9,stroke:#cfcfcf,color:#111,stroke-width:1.2px;")
        add("classDef cgw fill:#ffeef4,stroke:#ff9ac2,color:#5f1230;")

    seen_nodes: set[str] = set()
    seen_edges: set[Tuple[str,str]] = set()

    def emit(node_id: str, label: str, klass: str):
        if node_id in seen_nodes:
            return
        if use_styles and klass:
            add(f'{node_id}["{label}"]:::{klass}')
        else:
            add(f'{node_id}["{label}"]')
        seen_nodes.add(node_id)

    def edge(a: str, b: str):
        key = (a, b)
        if key in seen_edges:
            return
        add(f"{a} --> {b}")
        seen_edges.add(key)

    for sub_id, rgs in grouped.items():
        sub_name = None
        for _rg_items in rgs.values():
            for _r in _rg_items:
                if _r.get("subscriptionName"):
                    sub_name = _r["subscriptionName"]; break
            if sub_name: break
        sub_label = _esc(sub_name or sub_id)

        sub_node = f"sub_{_sid(sub_id)}"
        add(f'subgraph {sub_node}["Subscription: {sub_label}"]')
        add("direction TB")

        for rg, rg_items in rgs.items():
            rg_node = f"rg_{_sid(sub_id)}_{_sid(rg)}"
            add(f'  subgraph {rg_node}["Resource Group: {_esc(rg)}"]')
            add("  direction LR")

            # ---- PASS 1: nodes ----
            for res in rg_items:
                rtype = str(res.get("type","")).lower()
                name  = res.get("name") or _last(res.get("id",""))
                if not name: 
                    continue

                if rtype == "microsoft.compute/virtualmachines":
                    vm_id = f'vm_{_sid(name)}'
                    vm_size = res.get("vmSize") or _get(res, "properties.hardwareProfile.vmSize", "")
                    os_type = res.get("osType") or _get(res, "properties.storageProfile.osDisk.osType", "")
                    parts = [f"VM: {_esc(name)}"]
                    if vm_size: parts.append(f"Size: {_esc(vm_size)}")
                    if os_type: parts.append(f"OS: {_esc(os_type)}")
                    tags = res.get("tags") or {}
                    if tags:
                        kv = list(tags.items())[:2]
                        parts.append("Tags: " + ", ".join(f"{_esc(k)}={_esc(v)}" for k, v in kv))
                    emit(vm_id, "<br/>".join(parts), "vm")
                    dname = _get(res, "properties.storageProfile.osDisk.name", "")
                    if dname:
                        did = f'disk_{_sid(dname)}'
                        emit(did, f"OS Disk: {_esc(dname)}", "disk")
                        edge(vm_id, did)

                    # VM IP summary bubble
                    privs = [p for p in (res.get("private_ip_address") or []) if p]
                    pubs  = [p for p in (res.get("public_ip_address")  or []) if p]
                    if privs or pubs:
                        ip_id = f'vmips_{_sid(name)}'
                        ip_lines = []
                        if privs:
                            ip_lines.append("private " + ", ".join(_esc(x) for x in privs[:5]) + ("…" if len(privs) > 5 else ""))
                        if pubs:
                            ip_lines.append("public "  + ", ".join(_esc(x) for x in pubs[:5])  + ("…" if len(pubs)  > 5 else ""))
                        emit(ip_id, "<br/>".join(ip_lines), "ip")
                        edge(vm_id, ip_id)

                elif rtype == "microsoft.network/networkinterfaces":
                    emit(f'nic_{_sid(name)}', f"NIC: {_esc(name)}", "nic")

                elif rtype == "microsoft.network/virtualnetworks":
                    vnet_id = f'vnet_{_sid(name)}'
                    emit(vnet_id, f"VNet: {_esc(name)}", "vnet")
                    for sn in _get(res, "properties.subnets", []) or []:
                        sname = sn.get("name") or ""
                        if sname:
                            sn_id = f'subnet_{_sid(name)}_{_sid(sname)}'
                            emit(sn_id, f"Subnet: {_esc(sname)}", "subnet")
                            edge(vnet_id, sn_id)

                elif rtype == "microsoft.network/publicipaddresses":
                    ip = _get(res, "properties.ipAddress", "")
                    emit(f'pip_{_sid(name)}', f"Public IP: {_esc(name)}" + (br + _esc(ip) if ip else ""), "ip")

                elif rtype == "microsoft.compute/disks":
                    emit(f'disk_{_sid(name)}', f"Disk: {_esc(name)}", "disk")

                else:
                    nid, klass = resolve_node_id_and_class(rtype, name)
                    emit(nid, default_label_for_type(rtype, name), klass)

            # ---- PASS 2: edges ----
            for res in rg_items:
                rtype = str(res.get("type","")).lower()
                name  = res.get("name") or _last(res.get("id",""))
                if not name:
                    continue

                if rtype == "microsoft.compute/virtualmachines":
                    vm_id = f'vm_{_sid(name)}'
                    for ni in _get(res, "properties.networkProfile.networkInterfaces", []) or []:
                        nid = (ni.get("id") or "")
                        nic_name = _split_arm_id(nid).get("name") or _last(nid)
                        if nic_name:
                            nic_id = f'nic_{_sid(nic_name)}'
                            emit(nic_id, f"NIC: {_esc(nic_name)}", "nic")
                            edge(vm_id, nic_id)

                elif rtype == "microsoft.network/networkinterfaces":
                    nic_id = f'nic_{_sid(name)}'
                    for ipconf in _get(res, "properties.ipConfigurations", []) or []:
                        # subnet
                        subnet_id = _get(ipconf, "properties.subnet.id", "")
                        if subnet_id:
                            seg = _split_arm_id(subnet_id)
                            vnet_name, subnet_name = seg.get("vnet"), seg.get("subnet")
                            if vnet_name:
                                v_id = f'vnet_{_sid(vnet_name)}'
                                emit(v_id, f"VNet: {_esc(vnet_name)}", "vnet")
                                if subnet_name:
                                    s_id = f'subnet_{_sid(vnet_name)}_{_sid(subnet_name)}'
                                    emit(s_id, f"Subnet: {_esc(subnet_name)}", "subnet")
                                    edge(v_id, s_id)
                                    edge(nic_id, s_id)
                        # public IP
                        pip_ref = _get(ipconf, "properties.publicIPAddress.id", "")
                        if pip_ref:
                            pip_name = _split_arm_id(pip_ref).get("name") or _last(pip_ref)
                            if pip_name:
                                p_id = f'pip_{_sid(pip_name)}'
                                emit(p_id, f"Public IP: {_esc(pip_name)}", "ip")
                                edge(nic_id, p_id)

                # ---- PASS 2B: generic ARM-ID linking (catch-all) ----
                rtype2 = str(res.get("type", "")).lower()
                name2  = res.get("name") or _last(res.get("id", ""))
                if not name2:
                    continue
                src_id, src_class = resolve_node_id_and_class(rtype2, name2)
                emit(src_id, default_label_for_type(rtype2, name2), src_class)

                for jpath, target_id in iter_arm_ids(res.get("properties", {}), "properties"):
                    # Skip VM OS disk and NICs (already rendered by pretty rules)
                    if jpath.endswith("properties.storageProfile.osDisk.managedDisk.id"):
                        continue
                    if ".networkProfile.networkInterfaces" in jpath and jpath.endswith(".id"):
                        continue

                    seg = _split_arm_id(target_id)
                    tprov = (seg.get("provider") or "").lower()
                    ttype = (seg.get("type") or "").lower()
                    tname = seg.get("name") or _last(target_id)

                    if not (tprov and ttype and tname):
                        continue
                    if not tprov.startswith("microsoft."):
                        continue

                    # normalize vnet/subnet
                    if tprov == "microsoft.network" and ttype == "virtualnetworks" and seg.get("subnet"):
                        ttype_full = "microsoft.network/subnets"
                        tname_vn = seg.get("vnet") or ""
                        tname_sn = seg.get("subnet") or ""
                        tgt_id, tgt_class = resolve_node_id_and_class(ttype_full, f"{tname_vn}/{tname_sn}")
                        if tname_vn:
                            v_id, _ = resolve_node_id_and_class("microsoft.network/virtualnetworks", tname_vn)
                            emit(v_id, f"VNet: {_esc(tname_vn)}", "vnet")
                            edge(v_id, tgt_id)
                        emit(tgt_id, f"Subnet: {_esc(tname_sn)}", "subnet")
                        edge(src_id, tgt_id)
                        continue

                    ttype_full = f"{tprov}/{ttype}"
                    tgt_id, tgt_class = resolve_node_id_and_class(ttype_full, tname)
                    label = (
                        f"VNet: {_esc(tname)}" if ttype_full == "microsoft.network/virtualnetworks" else
                        f"NSG: {_esc(tname)}" if ttype_full == "microsoft.network/networksecuritygroups" else
                        f"Public IP: {_esc(tname)}" if ttype_full == "microsoft.network/publicipaddresses" else
                        default_label_for_type(ttype_full, tname)
                    )
                    emit(tgt_id, label, tgt_class)
                    edge(src_id, tgt_id)
            # ---- PASS 3: floating "Additional Details" per resource (if fields exist) ----
            meta_fields = ["vendor","business_service","provider_so","company_name","company","comapny_terp","tenantId","subscriptionId","resourceGroup","location","provisioningState","operationalState","ci_owner","tags","retired","id"]
            for res in rg_items:
                # Emit only if at least one field is present
                if not any((res.get(f) is not None) for f in meta_fields):
                    continue
                rname = res.get("name") or _last(res.get("id","")) or "resource"
                meta_lines: list[str] = []
                for k in meta_fields:
                    v = res.get(k, "—")
                    if isinstance(v, dict):
                        val = ", ".join(f"{_esc(kk)}={_esc(vv)}" for kk, vv in v.items())
                    else:
                        val = _esc(v)
                    meta_lines.append(f"<b>{_esc(k)}</b>: {val}")
                meta_html = "<br/>".join(meta_lines)
                add(f'  meta_{_sid(rname)}["Additional Details<br/>{meta_html}"]:::meta')
        
    add("  end")
    add("end")

    return "\n".join(lines)



# ---- App Gateway specialized renderer (Mermaid 11) ----
def render_app_gateway(obj: Dict[str, Any], direction: str = "LR", use_styles: bool = False) -> str:
    dir_token = "LR" if str(direction).upper() == "LR" else "TB"
    br = "<br/>"
    name = obj.get("name", "appgw")
    sub  = obj.get("subscriptionId", "") or _split_arm_id(obj.get("id","")).get("subscription","")
    rg   = obj.get("resourceGroup", "") or _split_arm_id(obj.get("id","")).get("resourceGroup","")
    props = obj.get("properties") or {}

    sku_tier = (obj.get("sku") or {}).get("tier") or (props.get("sku") or {}).get("tier") or "—"
    op_state = obj.get("operationalState") or props.get("operationalState") or "—"
    fe_priv  = obj.get("frontent_private_ip_address") or "—"
    fe_pub   = obj.get("frontent_public_ip_address") or "—"

    def idx_by_name(items):
        return { (x.get("name") or _name_from_id(x.get("id",""))): x for x in (items or []) }

    listeners = idx_by_name(props.get("httpListeners"))
    frontend_ports = idx_by_name(props.get("frontendPorts"))
    frontend_ips   = idx_by_name(props.get("frontendIPConfigurations"))
    pools          = idx_by_name(props.get("backendAddressPools"))
    http_settings  = idx_by_name(props.get("backendHttpSettingsCollection"))
    probes         = idx_by_name(props.get("probes"))
    rules          = idx_by_name(props.get("requestRoutingRules"))
    rewrite_sets   = idx_by_name(props.get("rewriteRuleSets"))
    ssl_certs      = idx_by_name(props.get("sslCertificates") or [])
    gw_ip_cfgs     = idx_by_name(props.get("gatewayIPConfigurations"))

    lines: List[str] = []
    add = lines.append

    add(f"flowchart {dir_token}")
    add(f'subgraph sub_{_sid(sub)}["Subscription: {_esc(sub)}"]')
    add("direction TB")
    add(f'  subgraph rg_{_sid(sub)}_{_sid(rg)}["Resource Group: {_esc(rg)}"]')
    add("  direction LR")

    agw_id = f"agw_{_sid(name)}"
    agw_label = f"App Gateway: {_esc(name)}{br}Tier: {_esc(sku_tier)}{br}State: {_esc(op_state)}{br}FE Private: {_esc(fe_priv)}{br}FE Public: {_esc(fe_pub)}"
    add(f'  {agw_id}["{agw_label}"]:::agw')

    for fname, fip in frontend_ips.items():
      fnode = f"fip_{_sid(fname)}"
      add(f'  {fnode}["FrontendIP: {_esc(fname)}"]:::nic')
      add(f'  {agw_id} --> {fnode}')
      pip_id = ((fip.get("properties") or {}).get("publicIPAddress") or {}).get("id")
      if pip_id:
        pip_name = _name_from_id(pip_id); pip_node = f"pip_{_sid(pip_name)}"
        add(f'  {pip_node}["Public IP: {_esc(pip_name)}"]:::ip')
        add(f'  {fnode} --> {pip_node}')

    for fname, fp in frontend_ports.items():
      port  = (fp.get("properties") or {}).get("port"); node  = f"fp_{_sid(fname)}"
      add(f'  {node}["Frontend Port: {_esc(fname)}{br}{_esc(port)}"]:::ip'); add(f'  {agw_id} --> {node}')

    for lname, lis in listeners.items():
      lp    = lis.get("properties") or {}
      proto = lp.get("protocol",""); hosts = ", ".join(lp.get("hostNames",[]) or []); node  = f"lis_{_sid(lname)}"
      add(f'  {node}["Listener: {_esc(lname)}{br}{_esc(proto)}{br}{_esc(hosts)}"]:::lb'); add(f'  {agw_id} --> {node}')
      fp_id = _name_from_id((lp.get("frontendPort") or {}).get("id","")); fip_id = _name_from_id((lp.get("frontendIPConfiguration") or {}).get("id",""))
      if fp_id: add(f'  {node} --> fp_{_sid(fp_id)}')
      if fip_id: add(f'  {node} --> fip_{_sid(fip_id)}')
      sc_id = _name_from_id((lp.get("sslCertificate") or {}).get("id",""))
      if sc_id: add(f'  cert_{_sid(sc_id)}["SSL Cert: {_esc(sc_id)}"]:::lb'); add(f'  {node} --> cert_{_sid(sc_id)}')

    for bname, bp in pools.items():
      bnode = f"bpool_{_sid(bname)}"; add(f'  {bnode}["Backend Pool: {_esc(bname)}"]:::lb')
      for addr in (bp.get("properties") or {}).get("backendAddresses", []) or []:
        leaf = addr.get("fqdn") or addr.get("ipAddress") or "backend"; lnode = f"bpitem_{_sid(bname)}_{_sid(leaf)}"
        add(f'  {lnode}["{_esc(leaf)}"]'); add(f'  {bnode} --> {lnode}')
      add(f'  {agw_id} --> {bnode}')

    for hname, hs in http_settings.items():
      hp    = hs.get("properties") or {}; port  = hp.get("port"); proto = hp.get("protocol","")
      hostn = hp.get("hostName","") or ("pickFromBackend" if hp.get("pickHostNameFromBackendAddress") else "")
      node  = f"bhs_{_sid(hname)}"; extra = (br + _esc(hostn)) if hostn else ""
      add(f'  {node}["HTTP Settings: {_esc(hname)}{br}{_esc(proto)}:{_esc(port)}{extra}"]:::lb'); add(f'  {agw_id} --> {node}')

    for pname, pr in probes.items():
      pp    = pr.get("properties") or {}; path  = pp.get("path","/"); proto = pp.get("protocol",""); node  = f"probe_{_sid(pname)}"
      add(f'  {node}["Probe: {_esc(pname)}{br}{_esc(proto)} {_esc(path)}"]:::lb'); add(f'  {agw_id} --> {node}')
      for h in (pp.get("backendHttpSettings") or []):
        hname = _name_from_id(h.get("id","")); 
        if hname: add(f'  {node} --> bhs_{_sid(hname)}')

    waf_id = (props.get("firewallPolicy") or {}).get("id")
    if waf_id:
      waf_name = _name_from_id(waf_id); node = f"waf_{_sid(waf_name)}"
      add(f'  {node}["WAF Policy: {_esc(waf_name)}"]:::fw'); add(f'  {agw_id} --> {node}')

    for gname, gw in gw_ip_cfgs.items():
      gnode = f"gwip_{_sid(gname)}"; add(f'  {gnode}["Gateway IP: {_esc(gname)}"]:::lb'); add(f'  {agw_id} --> {gnode}')
      subnet_id = _get(gw, "properties.subnet.id", "")
      if subnet_id:
        seg = _split_arm_id(subnet_id); vn  = seg.get("vnet") or ""; sn  = seg.get("subnet") or ""
        if vn:
          add(f'  vnet_{_sid(vn)}["VNet: {_esc(vn)}"]:::vnet')
          if sn:
            add(f'  subnet_{_sid(vn)}_{_sid(sn)}["Subnet: {_esc(sn)}"]:::subnet')
            add(f'  vnet_{_sid(vn)} --> subnet_{_sid(vn)}_{_sid(sn)}'); add(f'  {gnode} --> subnet_{_sid(vn)}_{_sid(sn)}')

    for rname, rr in rules.items():
      rp    = rr.get("properties") or {}; prio  = rp.get("priority",""); rnode = f"rule_{_sid(rname)}"
      add(f'  {rnode}["Rule: {_esc(rname)}{br}Priority {_esc(prio)}"]:::lb'); add(f'  {agw_id} --> {rnode}')
      lis_id = _name_from_id((rp.get("httpListener") or {}).get("id","")); bhs_id = _name_from_id((rp.get("backendHttpSettings") or {}).get("id","")); bp_id = _name_from_id((rp.get("backendAddressPool") or {}).get("id",""))
      if lis_id: add(f'  lis_{_sid(lis_id)} --> {rnode}')
      if bhs_id: add(f'  {rnode} --> bhs_{_sid(bhs_id)}')
      if bp_id:  add(f'  {rnode} --> bpool_{_sid(bp_id)}')
      rrs_id = _name_from_id((rp.get("rewriteRuleSet") or {}).get("id",""))
      if rrs_id: add(f'  rrs_{_sid(rrs_id)}["Rewrite Set: {_esc(rrs_id)}"]:::lb'); add(f'  {rnode} --> rrs_{_sid(rrs_id)}')

    meta_keys = ["vendor","business_service","provider_so","company_name","company","comapny_terp","tenantId","subscriptionId","resourceGroup","location","provisioningState","operationalState","ci_owner","tags","retired","id"]
    meta_lines: List[str] = []
    for k in meta_keys:
      v = obj.get(k, "—")
      if isinstance(v, dict): val = ", ".join(f"{_esc(kk)}={_esc(vv)}" for kk, vv in v.items())
      else: val = _esc(v)
      meta_lines.append(f"<b>{_esc(k)}</b>: {val}")
    meta_html = "<br/>".join(meta_lines)
    add(f'  meta_{_sid(name)}["Additional Details<br/>{meta_html}"]:::meta')

    add("  end"); add("end")

    if use_styles:
      add("classDef agw fill:#fff8e1,stroke:#f57f17,stroke-width:1.5px,color:#222;")
      add("classDef ip  fill:#f0f7ff,stroke:#1976d2,color:#111;")
      add("classDef lb  fill:#f9f9f9,stroke:#9e9e9e,color:#111;")
      add("classDef nic fill:#f9fff7,stroke:#2e7d32,color:#111;")
      add("classDef fw  fill:#fff0f0,stroke:#c62828,color:#111;")
      add("classDef vnet fill:#eef6ff,stroke:#90b4ff,color:#0e1b4d;")
      add("classDef subnet fill:#f2f7ff,stroke:#bdd0ff,color:#0e1b4d;")
      add("classDef meta fill:#f6f6ff,stroke:#9c27b0,color:#222,stroke-width:1.2px;")

    return "\n".join(lines)


def _name_from_id(i: str) -> str:
    return i.split('/')[-1] if i else ''