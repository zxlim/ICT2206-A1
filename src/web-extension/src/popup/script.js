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

const btnDohChoiceSave = document.querySelector("#btn-doh-choice-save");
const divDohCustom = document.querySelector("#div-doh-custom");
const inputDohCustom = document.querySelector("#input-doh-custom");
const selectorDohChoice = document.querySelector("#selector-doh-choice");
const preferenceResponse = document.querySelector("#preference-response");
const verificationResponse = document.querySelector("#verification-response");

const getCurrentDohSelection = () => {
    browser.runtime
        .sendMessage({
            type: "getDohPreference",
        })
        .then((message) => {
            const { data } = message;

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
    browser.runtime
        .sendMessage({
            type: "harcValidationResult",
        })
        .then((message) => {
            let result = "";

            switch (message.data) {
                case "doh-failure":
                    // eslint-disable-next-line quotes
                    result = `<hr>\n<span class="text-bold text-warning">Cannot perform HARC validation</span>`;
                    break;
                case "ignored-domain":
                    // eslint-disable-next-line quotes
                    result = `<hr>\n<span class="text-muted">HARC not deployed on this website</span>`;
                    break;
                case "trusted":
                    // eslint-disable-next-line quotes
                    result = `<hr>\n<span class="text-bold text-success">Website content verified authentic</span>`;
                    break;
                case "trusted-mozilla":
                    // eslint-disable-next-line quotes
                    result = `<hr>\n<span>This is a secure Mozilla Firefox page</span>`;
                    break;
                case "untrusted":
                    // eslint-disable-next-line quotes
                    result = `<hr>\n<span class="text-bold text-danger">Website content is not authentic</span>`;
                    break;
                default:
                    break;
            }

            verificationResponse.innerHTML = result;
        })
        .catch(() => {
            // eslint-disable-next-line no-console
            console.error("[HARC] Failed to obtain HARC validation result.");
        });
};

const communicateDohPreference = async (choice, customDohServerAddr = null) => {
    const result = await browser.runtime.sendMessage({
        type: "setDohPreference",
        data: {
            choice: choice,
            customDohServerAddr: customDohServerAddr,
        },
    });

    preferenceResponse.textContent = result.message;
};

const entrypoint = async () => {
    getCurrentDohSelection();
    getHarcValidationResult();

    selectorDohChoice.addEventListener("change", async (event) => {
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

    btnDohChoiceSave.addEventListener("click", async () => {
        const choice = selectorDohChoice.value.trim();

        if (choice === "custom") {
            await communicateDohPreference(choice, inputDohCustom.value.trim());
        } else {
            await communicateDohPreference(choice);
        }
    });
};

entrypoint();
