# PX League – Blogger static pages

Every `/p/` link in the footer of `blogger/px-league-theme.xml` (column "معلومات" and
"روابط سريعة"). Live status checked on 2026-11-20.

## Legal pages (paste the file into the page's HTML view)

| File | Title to type FIRST (sets the URL) | Final Arabic title | URL | Status 2026-11-20 |
|---|---|---|---|---|
| `about-us.html` | `about-us` | من نحن | https://www.px-league.site/p/about-us.html | 404, create |
| `privacy-policy.html` | `privacy-policy` | سياسة الخصوصية | https://www.px-league.site/p/privacy-policy.html | 404, create |
| `terms-of-use.html` | `terms-of-use` | شروط الاستخدام | https://www.px-league.site/p/terms-of-use.html | 404, create |
| `disclaimer.html` | `disclaimer` | إخلاء المسؤولية | https://www.px-league.site/p/disclaimer.html | 404, create |
| `contact-us.html` | `contact-us` | اتصل بنا | https://www.px-league.site/p/contact-us.html | 404, create |

## Theme-rendered pages (any body text, the theme replaces it)

| Title to type FIRST | Final Arabic title | URL | Status 2026-11-20 |
|---|---|---|---|
| `news` | الأخبار | /p/news.html | 200 |
| `predictions` | التوقعات | /p/predictions.html | 200 |
| `standings` | الترتيب | /p/standings.html | 200 |
| `app` | التطبيق | /p/app.html | 200 |
| `match` | تفاصيل المباراة | /p/match.html | 200 |
| `matches` | مركز المباريات | /p/matches.html | 404, not linked from the footer; create it if you link to it |

## Getting the exact URL (Blogger sets it from the FIRST published title)

Blogger builds a page's permalink from its title when the page is first published, and
an Arabic title gives a meaningless `/p/blog-page_123.html`. So, for each page:

1. Blogger → **Pages** → **New page**.
2. Title: type the slug in English, e.g. `about-us`.
3. Switch the editor to **HTML view** and paste the whole file content.
4. **Publish**. The URL is now `/p/about-us.html` and it never changes again.
5. Open the page again, change the title to the Arabic one (e.g. `من نحن`), **Update**.
6. Optional: Page settings → **Search description** → write one sentence; the theme
   uses it as the meta / og description of the page.

If a page with the same slug existed before (including a deleted one), Blogger may add a
suffix such as `_1` (`/p/about-us_1.html`), and the footer link stays 404. Check the URL
right after publishing; if it has a suffix, edit the old page instead of creating a new one.

Before publishing, replace `contact@px-league.site` (privacy, terms, contact pages) with an
address that actually receives mail, or create it (e.g. Cloudflare Email Routing → your inbox).

Each file is bilingual: the Arabic text is in `<div class="lang-ar" dir="rtl" lang="ar">` and
the English text in `<div class="lang-en" dir="ltr" lang="en">`. Paste the whole file once; the
theme (`html[lang="ar"] .lang-en` / `html[lang="en"] .lang-ar` → `display: none`) shows the
language picked with the header AR/EN button. The page title (outside the file) is translated
by the theme's dictionary.

The files use only `div`, `h2`, `p`, `ul`, `li`, `a`, `strong`, `em` (no inline styles), so the
theme's `.post-body` styles apply. `terms-of-use.html` has `id="dmca"` (Arabic) and
`id="dmca-en"` (English) on the takedown section; the disclaimer and contact pages link to the
anchor of their own language.

Check after publishing (every line must print 200):

```sh
for p in about-us privacy-policy terms-of-use disclaimer contact-us news predictions standings app; do
  printf "%-16s " $p; curl -s -o /dev/null -w "%{http_code}\n" "https://www.px-league.site/p/$p.html"; done
```
