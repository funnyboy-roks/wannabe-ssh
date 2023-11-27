const clients = document.querySelector('#clients');
const run = async () => {
    let res = await fetch('/api/is_authed');

    let authed = false;
    if (await res.text() === '1') {
        authed = true;
    }

    if (!authed) { // TODO
        return;
    }

    res = await fetch('/api/commands');
    // Map< client : actions >
    let json = await res.json();

    Object.entries(json).forEach(([k, v]) => {
        let div = document.createElement('div');
        let h1 = document.createElement('h1');
        h1.textContent = k;
        div.appendChild(h1);
        for (const action of v) {
            let button = document.createElement('button');
            button.addEventListener('click', async () => {
                let res = await fetch('/api/exec', {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/json',
                    },
                    body: JSON.stringify({
                        client: k,
                        action,
                    }),
                });
                if (res.status !== 200) {
                    alert(`Got status code: ${res.status}`);
                }
            });
            button.textContent = action;
            div.appendChild(button);
        }
        clients.appendChild(div);
    });
};

run();
