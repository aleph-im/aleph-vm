async function fetchApiStatus () {
    const q = await fetch('/status/check/fastapi');
    let res = {
        status: q.status,
        details: []
    }
    if(q.ok){
        res.status = "working properly &#9989;";
    }
    switch(Number(q.status)){
        case 503:
            res.status = "not working properly &#10060;";
            res.details = await q.json();
        case 500:
            res.status = "&#10060; Failed";
        default:
            res.status = q.status;
    }

    return res;
}

const buildQueryParams = (params) => Object.entries(params).reduce((acc, [k, v]) => acc + `${k}=${v}&`, '?').slice(0, -1);

const fetchLatestRelease = async () => {
    const q = await fetch('https://api.github.com/repos/aleph-im/aleph-vm/releases/latest');
    if(q.ok){
        return await q.json();
    }
}

const buildMetricViewset = (metricsMsg, crnId, metricsResult) => {
    const thisNode = metricsMsg.content.metrics.crn.find(node => node.node_id === crnId)
    const factory = keyName => ({ time: thisNode.measured_at, value: thisNode[keyName] * 100 })
    const keys = ['base_latency', 'base_latency_ipv4', 'diagnostic_vm_latency', 'full_check_latency']
    keys.map(key => metricsResult[key].push(factory(key)))
}

async function* fetchLatestMetrics (crnId, fromDate) {
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
    return [];

    const totalPages = Math.ceil(totalDataPoints / qp.pagination);
    let currentPage = 0;

    while(currentPage < totalPages){
        const q = await fetch(API_URL + buildQueryParams({...qp, page: currentPage + 1}));
        if(q.ok){
            const res = await q.json();
            res.posts.map(post => buildMetricViewset(post, crnId, data));
            currentPage++;
        }
        yield {
            progress: currentPage / totalPages,
            data
        };
    }
}