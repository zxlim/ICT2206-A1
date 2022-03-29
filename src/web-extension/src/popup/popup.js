/**
 * HTTP Authenticated Response Content (HARC):
 * Provides an additional layer of authentication through a Content Delivery Network.
 *
 * HARC Client-side Verifier Extension for Mozilla Firefox.
 *
 * @author     Daniel Tan Zhonghao  <2001240@sit.singaporetech.edu.sg>
 * @author     Ho Xiu Qi            <1802962@sit.singaporetech.edu.sg>
 * @author     Lim Zhao Xiang       <1802976@sit.singaporetech.edu.sg>
 * @copyright  Copyright (c) 2022. For the fulfillment of the SIT module
 *             ICT2206 Web Security (AY2021/2022, Trimester 2).
 */

const divDohCustom = document.querySelector("#div-doh-custom");
const inputDohCustom = document.querySelector("#input-doh-custom");
const selectorDohChoice = document.querySelector("#selector-doh-choice");

const getCurrentDohSelection = () => {
    browser.runtime
        .sendMessage({
            type: "getDohPreference",
        })
        .then((result) => {
            const { data } = result;

            for (let i = 0; i < selectorDohChoice.options.length; ++i) {
                if (selectorDohChoice.options[i].value === data.choice) {
                    selectorDohChoice.options[i].selected = "selected";
                    break;
                }
            }

            if (data.choice === "custom") {
                inputDohCustom.value = data.customDohServerAddr;
                divDohCustom.classList.remove("hidden");
            }
        })
        .catch(() => {
            // eslint-disable-next-line no-console
            console.error(
                "[HARC] Failed to obtain current DOH server preference.",
            );
        });
};

const getHarcValidationResult = () => {
    browser.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
        if (tabs.length === 0) {
            return;
        }

        browser.runtime
            .sendMessage({
                type: "harcValidationResult",
                tabId: tabs[0].id,
            })
            .then((result) => {
                let output = "";

                switch (result.data) {
                    case "doh-failure":
                        // eslint-disable-next-line quotes
                        output = `<hr>\n<span class="text-bold text-warning">Cannot perform HARC validation.</span>`;
                        break;
                    case "ignored-domain":
                        // eslint-disable-next-line quotes
                        output = `<hr>\n<span class="text-muted">HARC not deployed on this website.</span>`;
                        break;
                    case "trusted":
                        // eslint-disable-next-line quotes
                        output = `<hr>\n<span class="text-bold text-success">✅&nbsp;&nbsp;Website content verified authentic.</span>`;
                        break;
                    case "untrusted":
                        // eslint-disable-next-line quotes
                        output = `<hr>\n<span class="text-bold text-danger">❌&nbsp;&nbsp;Website content is not authentic.</span>`;
                        break;
                    default:
                        break;
                }

                document
                    .querySelector("#verification-response")
                    .classList.remove("hidden");
                document.querySelector(
                    "#verification-response-span",
                ).innerHTML = output;
            })
            .catch(() => {
                // eslint-disable-next-line no-console
                console.error(
                    "[HARC] Failed to obtain HARC validation result.",
                );
            });
    });
};

const communicateDohPreference = (choice, customDohServerAddr = null) => {
    browser.runtime
        .sendMessage({
            type: "setDohPreference",
            data: {
                choice: choice,
                customDohServerAddr: customDohServerAddr,
            },
        })
        .then((result) => {
            document
                .querySelector("#preference-response")
                .classList.remove("hidden");
            document.querySelector("#preference-response-span").textContent =
                result.data.message;
        });
};

const entrypoint = () => {
    document
        .querySelector("#btn-doh-choice-save")
        .addEventListener("click", () => {
            const choice = selectorDohChoice.value.trim();

            if (choice === "custom") {
                const customDohServerAddr = inputDohCustom.value.trim();
                if (customDohServerAddr.length === 0) {
                    inputDohCustom.reportValidity();

                    document
                        .querySelector("#preference-response")
                        .classList.remove("hidden");
                    document.querySelector(
                        "#preference-response-span",
                    ).textContent =
                        "Please fill in your custom DOH server address.";
                } else {
                    communicateDohPreference(choice, customDohServerAddr);
                }
            } else {
                communicateDohPreference(choice);
            }
        });

    selectorDohChoice.addEventListener("change", (event) => {
        const choice = event.target.value.trim();

        if (choice === "custom") {
            divDohCustom.classList.remove("hidden");
            inputDohCustom.disabled = false;
            inputDohCustom.readonly = false;
        } else {
            divDohCustom.classList.add("hidden");
            inputDohCustom.disabled = true;
            inputDohCustom.readonly = true;
        }
    });

    getCurrentDohSelection();
    getHarcValidationResult();
};

entrypoint();
