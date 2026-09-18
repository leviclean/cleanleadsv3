const encoder = new TextEncoder();
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function sign(payload, secret) {
  const body = b64url(encoder.encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign('HMAC', await hmacKey(secret), encoder.encode(body));
  return `${body}.${b64url(new Uint8Array(signature))}`;
}
async function verify(token, secret) {
  const [body, signature] = String(token || '').split('.');
  if (!body || !signature) throw new Error('Conexão inválida');
  const valid = await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64url(signature), encoder.encode(body));
  if (!valid) throw new Error('Conexão inválida');
  const payload = JSON.parse(new TextDecoder().decode(unb64url(body)));
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Conexão expirada');
  return payload;
}

const responseJson = (data, status, origin) => new Response(JSON.stringify(data), {
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': origin,
    'access-control-allow-headers': 'authorization,content-type',
    'access-control-allow-methods': 'GET,POST,OPTIONS'
  }
});
const stripeHeaders = (secret, account) => ({ authorization: `Bearer ${secret}`, ...(account ? { 'Stripe-Account': account } : {}) });

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const action = url.searchParams.get('action') || '';
    const appUrl = String(process.env.APP_URL || '').replace(/\/$/, '');
    const stripeSecret = process.env.STRIPE_SECRET_KEY || '';
    const clientId = process.env.STRIPE_CONNECT_CLIENT_ID || '';
    const tokenSecret = process.env.CONNECT_TOKEN_SECRET || '';
    const origin = appUrl ? new URL(appUrl).origin : '*';

    if (request.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,OPTIONS' } });

    try {
      if (!appUrl || !stripeSecret || !clientId || !tokenSecret) throw new Error('Integração Stripe não configurada na Vercel');

      if (action === 'connect') {
        const state = await sign({ exp: Math.floor(Date.now() / 1000) + 600 }, tokenSecret);
        const destination = new URL('https://connect.stripe.com/oauth/authorize');
        destination.search = new URLSearchParams({ response_type: 'code', client_id: clientId, scope: 'read_write', redirect_uri: `${url.origin}/api/stripe/callback`, state });
        return Response.redirect(destination.toString(), 302);
      }

      if (action === 'callback') {
        await verify(url.searchParams.get('state'), tokenSecret);
        const form = new URLSearchParams({ grant_type: 'authorization_code', code: url.searchParams.get('code') || '', client_secret: stripeSecret });
        const exchange = await fetch('https://connect.stripe.com/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form });
        const data = await exchange.json();
        if (!exchange.ok || !data.stripe_user_id) throw new Error(data.error_description || 'Não foi possível conectar a Stripe');
        const connection = await sign({ account: data.stripe_user_id, exp: Math.floor(Date.now() / 1000) + 31536000 }, tokenSecret);
        return Response.redirect(`${appUrl}#stripe_connection=${encodeURIComponent(connection)}`, 302);
      }

      const authorization = request.headers.get('authorization') || '';
      const connection = await verify(authorization.replace(/^Bearer\s+/i, ''), tokenSecret);

      if (action === 'me') {
        const stripeResponse = await fetch('https://api.stripe.com/v1/account', { headers: stripeHeaders(stripeSecret, connection.account) });
        const account = await stripeResponse.json();
        if (!stripeResponse.ok) throw new Error(account.error?.message || 'Conta Stripe indisponível');
        return responseJson({ id: account.id, name: account.business_profile?.name || account.settings?.dashboard?.display_name || 'Conta Stripe', chargesEnabled: !!account.charges_enabled }, 200, origin);
      }

      if (action === 'checkout' && request.method === 'POST') {
        const input = await request.json();
        const amount = Math.round(Number(input.amount) * 100);
        if (!Number.isFinite(amount) || amount < 50) throw new Error('Informe um valor válido');
        const form = new URLSearchParams();
        form.set('mode', 'payment');
        form.set('success_url', `${appUrl}#stripe_success={CHECKOUT_SESSION_ID}`);
        form.set('cancel_url', `${appUrl}#stripe_cancelled=1`);
        form.set('line_items[0][quantity]', '1');
        form.set('line_items[0][price_data][currency]', 'brl');
        form.set('line_items[0][price_data][unit_amount]', String(amount));
        form.set('line_items[0][price_data][product_data][name]', String(input.description || 'Pagamento CLEAN Leads').slice(0, 120));
        form.set('metadata[clean_leads]', 'true');
        form.set('metadata[client]', String(input.client || 'Cliente').slice(0, 120));
        const stripeResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', { method: 'POST', headers: { ...stripeHeaders(stripeSecret, connection.account), 'content-type': 'application/x-www-form-urlencoded' }, body: form });
        const session = await stripeResponse.json();
        if (!stripeResponse.ok) throw new Error(session.error?.message || 'Não foi possível criar o checkout');
        return responseJson({ id: session.id, url: session.url }, 200, origin);
      }

      if (action === 'status') {
        const id = url.searchParams.get('session_id') || '';
        if (!/^cs_/.test(id)) throw new Error('Checkout inválido');
        const stripeResponse = await fetch(`https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(id)}`, { headers: stripeHeaders(stripeSecret, connection.account) });
        const session = await stripeResponse.json();
        if (!stripeResponse.ok) throw new Error(session.error?.message || 'Não foi possível confirmar o pagamento');
        return responseJson({ id: session.id, paid: session.payment_status === 'paid', amount: Number(session.amount_total || 0) / 100, client: session.metadata?.client || 'Cliente' }, 200, origin);
      }

      return responseJson({ error: 'Rota não encontrada' }, 404, origin);
    } catch (error) {
      return responseJson({ error: error.message || 'Erro na integração Stripe' }, 400, origin);
    }
  }
};
