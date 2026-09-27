"""Strict network comparison; only bounded address-lifetime countdown is permitted."""
import copy, math

def compare_network(before, after, elapsed_seconds):
    if not isinstance(elapsed_seconds,(int,float)) or not math.isfinite(elapsed_seconds) or not 0 <= elapsed_seconds <= 60:
        raise ValueError('invalid capture interval')
    b,a=copy.deepcopy(before),copy.deepcopy(after)
    differences=[]
    maximum=math.ceil(elapsed_seconds)+1 # one-second quantization/capture boundary margin
    for family in ('addr4','addr6'):
        if family not in b or family not in a:continue
        if len(b[family])!=len(a[family]):return False,[]
        for i,(old,new) in enumerate(zip(b[family],a[family])):
            if old.get('ifname')!=new.get('ifname'):return False,[]
            x,y=old.get('addr_info',[]),new.get('addr_info',[])
            if len(x)!=len(y):return False,[]
            for j,(oa,na) in enumerate(zip(x,y)):
                for key in ('preferred_life_time','valid_life_time'):
                    if key not in oa or key not in na:continue
                    ov,nv=oa[key],na[key]
                    if ov==nv:continue
                    if type(ov) is not int or type(nv) is not int or not 0 <= nv <= ov or ov-nv>maximum:return False,[]
                    differences.append({'interface':old['ifname'],'family':family,'address_index':j,'field':key,'before':ov,'after':nv})
                    na[key]=ov
    return a==b,differences
