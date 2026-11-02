import { writeFile } from 'node:fs/promises';

export async function getToken(
    authority: string,
    audience: string,
    clientId: string,
    clientSecret: string,
    scope: string
): Promise<string> {
    const cleanAuthority = authority.replace(/\/$/, '');
    const response = await fetch(`${cleanAuthority}/oauth/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            grant_type: 'client_credentials',
            client_id: clientId,
            client_secret: clientSecret,
            audience,
            scope,
        }),
    });

    if (!response.ok) {
        throw new Error(`Neuspješno dohvaćanje tokena. Status: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as { access_token?: string };
    if (!data.access_token) {
        throw new Error('Odgovor poslužitelja ne sadrži access_token.');
    }

    return data.access_token;
}

export async function issuePass(
    url: string,
    token: string,
    name: string,
    document: string
): Promise<void> {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, document }),
    });

    if (!response.ok) {
        throw new Error(`Neuspješno izdavanje propusnice. Status: ${response.status} ${response.statusText}`);
    }

    const locationHeader = response.headers.get('Location') || response.headers.get('location');
    if (!locationHeader) {
        throw new Error('Odgovor poslužitelja ne sadrži Location zaglavlje.');
    }

    const passId = locationHeader.split('/').pop();
    if (!passId) {
        throw new Error('Nije moguće izdvojiti identifikator propusnice iz Location zaglavlja.');
    }

    const buffer = Buffer.from(await response.arrayBuffer());
    await writeFile(`${passId}.png`, buffer);
}
