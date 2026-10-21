"""RFC 7636 appendix B values shared by session-code tests."""

VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
PKCE_BODY = {
    'code_challenge': CHALLENGE,
    'code_challenge_method': 'S256',
}
