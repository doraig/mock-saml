import { createHash } from 'crypto';
import config from 'lib/env';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { User } from 'types';
import saml from '@boxyhq/saml20';
import { getEntityId } from 'lib/entity-id';
import { logger } from "logger"
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { email, audience, acsUrl, id, relayState, claims } = req.body;
    logger.info(`Claims ${claims}`);
    let responseClaims;
    try {
      responseClaims = JSON.parse(claims);
    }
    catch (e) {
      res.status(403).send(`Invalid claims: ${claims}`);
    }
    if (!email.endsWith('@example.com') && !email.endsWith('@example.org')) {
      res.status(403).send(`${email} denied access`);
    }

    const userId = createHash('sha256').update(email).digest('hex');
    const userName = email.split('@')[0];

    const user: User = {
      id: userId,
      email,
      firstName: userName,
      lastName: userName,
    };
    logger.info(`User ${user.email} logged in, sending SAML response`);
    const xmlSigned = await saml.createSAMLResponse({
      issuer: getEntityId(config.entityId, req.query.namespace as any),
      audience,
      acsUrl,
      requestId: id,
      claims: {
        raw: {
          ...user,
          ...(Object.keys(responseClaims).length > 0 ? responseClaims : process.env.CLAIM_DATA ? JSON.parse(process.env.CLAIM_DATA) : {} )
        },
        email: user.email,
      },
      privateKey: config.privateKey,
      publicKey: config.publicKey,
    });

    const encodedSamlResponse = Buffer.from(xmlSigned).toString('base64');
    const html = saml.createPostForm(acsUrl, [
      {
        name: 'RelayState',
        value: relayState,
      },
      {
        name: 'SAMLResponse',
        value: encodedSamlResponse,
      },
    ]);
    res.send(html);
  } else {
    res.status(405).send(`Method ${req.method} Not Allowed`);
  }
}
