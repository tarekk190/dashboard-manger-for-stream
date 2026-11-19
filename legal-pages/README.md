# PX League – legal pages (Blogger static pages)

The footer of `blogger/px-league-theme.xml` links to these exact URLs:

| File | Page title (Arabic) | Blogger URL |
|---|---|---|
| `about-us.html` | من نحن | https://www.px-league.site/p/about-us.html |
| `privacy-policy.html` | سياسة الخصوصية | https://www.px-league.site/p/privacy-policy.html |
| `terms-of-use.html` | شروط الاستخدام | https://www.px-league.site/p/terms-of-use.html |
| `contact-us.html` | اتصل بنا | https://www.px-league.site/p/contact-us.html |
| `disclaimer.html` | إخلاء المسؤولية | https://www.px-league.site/p/disclaimer.html |

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

Before publishing, replace `contact@px-league.site` (privacy policy + contact page) with an
address that actually receives mail, or create it (e.g. Cloudflare Email Routing → your inbox).

If a page already exists with another URL (the old footer used `/p/about.html`,
`/p/privacy.html`, `/p/contact.html`), delete or keep it, but the footer now points to the
URLs above.
