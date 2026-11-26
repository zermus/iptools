const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const source = fs.readFileSync(__dirname + '/../mtr.php', 'utf8');
const script = source.split('<script nonce="<?php echo $nonce; ?>">')[1].split('</script>')[0]
    .replace(/<\?php echo rawurlencode\(\$runId\); \?>/g, 'owned')
    .replace(/<\?php echo \(int\)\(\$tracerouteTimeout \+ 10\) \* 1000; \?>/g, '70000');

async function scenario(responses, expected, options = {}) {
    let now = 0, nextId = 0, active = 0, maxActive = 0, requests = 0;
    const timers = new Map();
    const output = {innerHTML: '', textContent: ''}, spinner = {style: {display: ''}};
    const context = {
        window: {addEventListener() {}},
        document: {getElementById: id => id === 'output' ? output : spinner},
        AbortController,
        setTimeout(fn, delay) { const id = ++nextId; timers.set(id, {fn, at: now + delay}); return id; },
        clearTimeout(id) { timers.delete(id); },
        fetch(url, {signal}) {
            assert.equal(active, 0, 'polls never overlap');
            active++; maxActive = Math.max(maxActive, active); requests++;
            const response = responses.shift() || {ok: false};
            return new Promise((resolve, reject) => {
                let settled = false;
                const finish = () => { if (settled) return; settled = true; active--; return true; };
                signal.addEventListener('abort', () => { if (finish()) reject(Error('aborted')); });
                context.setTimeout(() => {
                    if (!finish()) return;
                    if (response.error) return reject(Error('offline'));
                    resolve({ok: response.ok !== false,
                        headers: {get: () => response.status || null},
                        text: () => {
                            assert(response.ok !== false && ['running', 'complete'].includes(response.status),
                                'unexpected bodies are never read');
                            return Promise.resolve(response.body || '&lt;safe&gt;');
                        }});
                }, response.delay || 1);
            });
        }
    };
    vm.createContext(context); vm.runInContext(script, context); context.window.onload();
    for (let i = 0; timers.size && i < 200; i++) {
        const [id, timer] = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
        timers.delete(id); now = timer.at; timer.fn();
        for (let j = 0; j < 12; j++) await Promise.resolve();
    }
    assert.equal(spinner.style.display, 'none', 'terminal states hide spinner');
    assert.equal(active, 0, 'terminal states abort outstanding requests');
    assert.equal(timers.size, 0, 'terminal states leave no stale updates');
    assert.equal(maxActive, 1);
    if (expected === 'complete') assert.equal(output.innerHTML, '&lt;safe&gt;');
    else assert(output.textContent.includes(expected), 'terminal message uses textContent');
    if (options.requests) assert.equal(requests, options.requests);
}
(async () => {
    await scenario([{status: 'running', delay: 7000}, {status: 'complete'}], 'complete', {requests: 2});
    await scenario([{error: true}, {ok: false}, {status: 'running'}, {}, {status: 'invalid'},
        {status: 'complete'}], 'complete', {requests: 6});
    await scenario([{}, {status: 'invalid'}, {ok: false, body: '<script>unsafe</script>'}], 'Unable', {requests: 3});
    await scenario([{delay: 20000}, {error: true}, {ok: false}], 'Unable', {requests: 3});
    await scenario(Array(20).fill({status: 'running', delay: 7000}), 'timed out');
    console.log('All 5 deterministic MTR polling scenarios passed.');
})().catch(error => { console.error(error); process.exit(1); });
