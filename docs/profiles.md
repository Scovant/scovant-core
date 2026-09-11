# Profiles

Some checks only make sense for a particular kind of site — an OpenAPI
discovery check has nothing to evaluate on a blog, and a Product/Offer
structured-data check has nothing to evaluate on a documentation site. Core
resolves one **profile** per scan so profile-scoped checks know what to
expect; a check outside the resolved profile returns `N/A`, never `FAIL`.

## The five profiles

```text
auto        not a profile itself — the resolution mode (the default)
content     blogs, docs, marketing sites, portfolios — the fallback profile
commerce    sites that sell a product
saas        sites that sell a subscription/service
api         sites whose primary surface is a documented API
```

`--profile` accepts any of the five. Passing anything other than `auto`
pins the profile directly (`profile_confidence = 1.0`) and skips resolution
entirely.

## Deterministic resolution (`auto`)

Resolution (`profiles.resolve_profile`) reads only evidence already
gathered for the scan — it fetches nothing itself — and applies these
rules in order, each returning as soon as it matches:

1. **`commerce`, confidence 0.95** — the sampled pages contain a
   commerce-typed schema.org entity (`Product`, `Offer`, `AggregateOffer`,
   or `ProductGroup`) **and** an add-to-cart semantic signal was found.
2. **`commerce`, confidence 0.85** — a commerce-typed schema.org entity (or
   other product-data evidence) was found, but no add-to-cart signal.
3. **`api`, confidence 0.9** — an OpenAPI document was discovered **and**
   an internal link references `/docs`, `/api`, or `/developers`.
4. **`api`, confidence 0.75** — an OpenAPI document was discovered but no
   docs-shaped link was found.
5. **`saas`, confidence 0.8** — a pricing-shaped link (`/pricing` or
   `/plans`) **and** a signup call-to-action were both found.
6. **`saas`, confidence 0.6** — only one of the two (pricing-shaped link
   or signup CTA) was found.
7. **`api`, confidence 0.55** — no commerce/pricing/signup signal, but a
   docs-shaped internal link (`/docs`, `/api`, `/developers`) was found.
8. **`content`, confidence 0.5** — none of the above matched. This is the
   fallback: every site that isn't recognisably commerce, SaaS, or API
   ends up scored as `content`.

Commerce-typed schema.org detection also walks one level of `@graph`
nesting, so a `Product`/`Offer` node embedded inside a graph-shaped JSON-LD
document is still recognised.

`profile_confidence` is reported on every scan (`Target.profile_confidence`)
so a caller can see how strong the resolution signal was — a low-confidence
`saas`/`api` result (0.55–0.6) reflects a genuinely ambiguous site, not a
scanner bug.
