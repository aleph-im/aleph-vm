
// Add optional "legacy" argument to this function
async function fetchFastapiCheckStatus (legacy = false) {
    const path = legacy ? '/status/check/fastapi/legacy' : '/status/check/fastapi';
    const q = await fetch(path);
    let res = {
        status: q.status,
        details: []
    }
    if(q.ok){
        res.status = " is working properly &#9989;";
    }
    else {
        switch(Number(q.status)){
            case 503:
                res.status = " is not working properly &#10060;";
                res.details = await q.json();
                break;
            case 500:
                res.status = " &#10060; Failed";
                break;
            default:
                res.status = q.status;
        }
    }

    return res;
}

async function fetchHostCheckStatus () {
    const q = await fetch('/status/check/host');
    let res = {
        status: q.status,
        details: []
    }
    if(q.ok){
        res.status = " is working properly &#9989;";
    }
    else {
        switch(Number(q.status)){
            case 503:
                res.status = " is not working properly &#10060;";
                res.details = await q.json();
                break;
            case 500:
                res.status = " &#10060; Failed";
                break;
            default:
                res.status = q.status;
        }
    }

    return res;
}

async function fetchHostSystemUsage () {
    const q = await fetch('/about/usage/system');
    let res = {
        status: q.status,
        details: []
    }
    if(q.ok){
        const answer = await q.json();
        const gpu_devices = answer.gpu.devices;
        if (gpu_devices.length <= 0) {
            res.status = "<b>No GPUs detected</b>";
        }else{
            res.status = "<ul>";
            for (const gpu_device of gpu_devices){
                let compatible_str = " is compatible &#9989;";
                if (!gpu_device.compatible) {
                    compatible_str = " isn't compatible &#10060;";
                }
                res.status += "<li><b>" + gpu_device.vendor + " | " + gpu_device.device_name + "</b>" + compatible_str + "</li>";
            }
            res.status += "</ul>";
        }
    }
    else {
        switch(Number(q.status)){
            case 500:
                res.status = "Getting Node usage failed &#10060;";
                break;
            default:
                res.status = q.status;
        }
    }

    return res;
}

function objectToString (obj) {
    return Object.entries(obj).reduce((acc, [k, v]) => acc + `<li>${k}: <span style="color: ${v ? 'green' : 'red'}">${v}</span></li>\n`, '');
}

const buildQueryParams = (params) => Object.entries(params).reduce((acc, [k, v]) => acc + `${k}=${v}&`, '?').slice(0, -1);

const isLatestRelease = async () => {
    const q = await fetch('https://api.github.com/repos/aleph-im/aleph-vm/releases/latest');
    if(q.ok){
        const res = await q.json();
        return res.tag_name
    }
    throw new Error('Failed to fetch latest release');
}

const buildMetricViewset = (metricsMsg, hostname, metricsResult) => {
    const thisNode = metricsMsg.content.metrics.crn.find(node => node.url === hostname)
    // Fixes a bug if a node has no metrics for the given timeframe
    if(thisNode){
        const factory = keyName => ({ time: thisNode.measured_at, value: thisNode[keyName] * 100 })
        const keys = ['base_latency', 'base_latency_ipv4', 'diagnostic_vm_latency', 'full_check_latency']
        keys.map(key => metricsResult[key].push(factory(key)))
    }
}

async function* fetchLatestMetrics (hostname, fromDate) {
    const defaultWindowSize = 50;
    const API_URL = 'https://api2.aleph.im/api/v0/posts.json';

    const data = {
        base_latency: [],
        base_latency_ipv4: [],
        diagnostic_vm_latency: [],
        full_check_latency: [],
    }

    const qp = {
        startDate: fromDate / 1000 | 0,
        types: 'aleph-network-metrics',
        pagination: defaultWindowSize
    }
    const count = await fetch(API_URL + buildQueryParams({...qp, pagination: 1}));
    if(!count.ok)
        throw new Error('Failed to fetch metrics');
    const countRes = await count.json();
    const totalDataPoints = countRes.pagination_total;

    if(totalDataPoints === 0)
        throw new Error('No metrics found');

    if(!countRes?.posts[0]?.content?.metrics?.crn?.find(node => node.url === hostname))
        throw new Error('Hostname not found in metrics');


    const totalPages = Math.ceil(totalDataPoints / qp.pagination);
    let currentPage = 0;
    let retries = 0;
    const RETRY_THRESHOLD = 5;

    while(currentPage < totalPages){
        if(retries > RETRY_THRESHOLD)
            throw new Error('Network error: too many retries')

        const q = await fetch(API_URL + buildQueryParams({...qp, page: currentPage + 1}));
        if(q.ok){
            const res = await q.json();
            res.posts.map(post => buildMetricViewset(post, hostname, data));
            currentPage++;
            yield {
                progress: currentPage / totalPages,
                data
            };
        }
        else{
            retries++;
        }
    }
}
