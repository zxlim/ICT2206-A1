/**
 * HTTP Authenticated Response Content (HARC):
 * Provides an additional layer of authentication through a Content Delivery Network.
 *
 * HARC Client-side Verifier Extension for Mozilla Firefox.
 * Block page script.
 *
 * @author     Daniel Tan Zhonghao  <2001240@sit.singaporetech.edu.sg>
 * @author     Ho Xiu Qi            <1802962@sit.singaporetech.edu.sg>
 * @author     Lim Zhao Xiang       <1802976@sit.singaporetech.edu.sg>
 * @copyright  Copyright (c) 2022. For the fulfillment of the SIT module
 *             ICT2206 Web Security (AY2021/2022, Trimester 2).
 */

const BLOCK_PAGE_HEAD = `<title>Privacy error</title>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'sha256-KX6k9/bRrS/AgJ7LAm41RdUmEaUbUBHITRmaIGamMUE=';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>body{margin:0;padding:0;background:#1d1f20;font-family:system-ui,sans-serif;margin:24px;color:#fff}.info{min-height:600px;margin:25vh auto 0;display:flex;justify-content:center;align-items:center;flex-direction:column}.title{margin:25px 0 0 0;font-style:normal;font-weight:700;font-size:46px;line-height:54px}.description{max-width:760px;margin:10px 0 0 0;text-align:center;font-weight:700;font-size:18px;line-height:21px;flex-grow:1}.highlight{color:#ff79c6}.small{font-size:14px}.icon{height:72px;width:72px;background-repeat:no-repeat;background-size:100%;background-image:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJAAAACQCAYAAADnRuK4AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAScSURBVHgB7Z1LVhsxEAAFL0cie3KyHC3sQ85EsKEB47GtkVpSf6o22eUx3aV68wbjKQU++FfK7wLQwt9SHp9LeTn8W6Ca+wJH7t7rc0eFdoFA5a0+5bM8j1SoHgQq59WhQvWkF+hbfQQqVEl6gS7VhgrVkVqgC/URqFAFqQW6VRkqdJu0At2oj0CFbpBWoNq6UKHrpBSosj4CFbpCSoH2VoUKXSadQDvrI1ChC6QTqLUmVGibVAI11kegQhukEqi3IlTonDQCddZHoELfSCOQVj2o0CkpBFKqj0CFvpBCIO1qUKFPwgukXB+BCr0TXqBRtaBCb4QWaFB9BCpUggs0uhJUKLBAg+sjpK9QWIFm1SF7hUIKNKk+QuoKhRRodhUyVyicQJPrI6StUDiBVtUga4VCCbSoPkLKCoUSaHUFMlYojECL6yOkq1AYgayc/mwVCiGQkfoIqSoUQiBrpz5ThdwLZKw+QpoKuRfI6mnPUiHXAhmtj5CiQq4Fsn7KM1TIrUDG6yOEr5Bbgbyc7ugVcimQk/oIoSvkUiBvpzpyhe6KMw6n+fWH/lMUeKi4/sP7M4oCr//Jr5+lPJVguCuQ19MctUKuBHJ27/OdkPdCrgTyfoojVsiNQM7rI4SrkBuBopzeaBVyIVCQ+gihKuRCoGinNtL1mBcoWH2EMBUyL1DU5ydRrsu0QEHrI4SokGmBov8mO8L1mRUoeH0E9xUyK1CWzxR7v06TAiWpj+C6QiYFyvbXnZ6v15xAyeojuK2QOYGyfs+O1+s2JVDS+gguK2RKoOzfeOrx+s0IlLw+grsKmRGIb31/w9scTAhEfU5wVSETAlGfUzzNY7lA1GcTNxVaLhD12cbLXJYKRH2u4qJCSwWiPtfxMJ9lAlGfKsxXaJlA1KcO63NaIhD12YXpCi0RiPrsw/K8pgtEfZowW6HpAlGfNqzObapA1KcLkxWaKhD16cPi/KYJRH1UMFehaQJRHx2szXGKQNRHFVMVmiIQ9dHF0jyHC0R9hmCmQsMFoj5jsDLXoQJRn6GYqNBQgajPWCzMd5hA1GcKyys0TCDqM4fVcx4iEPWZytIKDRGI+sxl5bzVBaI+S1hWIXWBqM8aVs1dVSDqs5QlFVIViPqsZcX81QSiPiaYXiE1gaiPDWbvQeWtzZpvUoZ+Xia+IVqlQNTHFjP30S0Q9z4mmXYv1C0Q9bHJrL10CUR9TDOlQl0CUR/bzNhPs0DUxwXDK9QsEPXxweg9NQlEfVwxtEI/SgNR6vNQ8SD1+fhczjfv+3oqA9hdIOrjkmEV2i0Q9z4+GbW3XQJRH9cMqdAugaiPb0bsr1og6hMC9QpVC0R9YqC9xyqBqE8oVCtUJRD1iYXmPm8+SOPThjHR+tTizQJRn5ho7fWqQNz7hEblXuiqQNQnNhr7vSgQ9UlBd4UuCkR9ctC7502BqE8quiq0KRD1yUXPvs8Eoj4paa7QmUDUJyetez8RiPqkpqlCJwJRn9y07P9DIOoDpaFCHwJRHziw14OjQNQHvrCrQkeBqA98ZY8P99QHNqiu0D31gS3wAgAAAAAAAAAAANT4DzoN/OFNCR08AAAAAElFTkSuQmCC)}</style>`;

const BLOCK_PAGE_BODY = `<div class="info">
<div class="icon" id="icon"></div>
<div class="title">Your connection is not private</div>
<div class="description">
<p class="highlight">The authenticity of this website cannot be established as HARC validation has failed.</p>
<div class="small">
<p>For your safety, this website has been automatically blocked from loading as HARC enforcement (strict mode) has been configured by the website owner.</p>
<p>Network errors and attacks are usually temporary, so this page will probably work correctly later.</p>
</div>
</div>
<footer class="footer-text">HTTP Authenticated Response Content (HARC)</footer>
</div>`;

document.head.innerHTML = BLOCK_PAGE_HEAD;
document.body.innerHTML = BLOCK_PAGE_BODY;
