"use strict";

function ee2e_form(form_id) {
    document.getElementById(form_id).onsubmit = async (e) => {
        e.preventDefault();

        let h1 = document.createElement("h1");
        h1.innerText = "Executing form request... (may take some time)"
        document.body.prepend(h1);

        let k = new Uint8Array(
            atob(_K)
                .split("")
                .map((c) => c.charCodeAt(0)),
        );

        let v = new Uint8Array(
            atob(_V)
                .split("")
                .map((c) => c.charCodeAt(0)),
        );

        let elements = e.target.elements;
        let obj = {};

        for (let idx = 0; idx < elements.length; ++idx) {
            let item = elements.item(idx);
            if (item.name) obj[item.name] = item.value;
        }

        let json = JSON.stringify(obj);
        let encoder = new TextEncoder();

        let data = encoder.encode(json);
        let ckey = await window.crypto.subtle.importKey(
            "raw",
            k,
            { name: "AES-CBC", length: 256 },
            false,
            ["encrypt"],
        );

        document.write(
            await (
                await fetch(window.location.href, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/octet-stream",
                    },
                    body: await window.crypto.subtle.encrypt(
                        { name: "AES-CBC", iv: v },
                        ckey,
                        data,
                    ),
                })
            ).text(),
        );
    };
}
