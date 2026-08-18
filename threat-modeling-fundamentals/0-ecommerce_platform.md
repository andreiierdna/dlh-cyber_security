# E-commerce Platform Threat Model

## System Overview

The e-commerce platform supports:

- Product browsing without authentication
- Adding items to a cart without authentication
- Checkout and payment for authenticated users
- Viewing order history for authenticated users

### Architecture

- **Frontend:** React
- **Backend:** Node.js API
- **Database:** PostgreSQL
- **Payment provider:** Stripe

---

## 1. STRIDE Threats for the Checkout Process

| STRIDE Category | Threat Description | Potential Impact | Suggested Mitigation |
|---|---|---|---|
| **Tampering** | A user modifies the checkout request from the React frontend, such as changing a product price, quantity, discount, or total before sending it to the Node.js API. | The attacker may purchase goods for less than the intended price, abuse discounts, or cause financial loss. | Never trust prices or totals supplied by the client. The backend should retrieve authoritative product prices from PostgreSQL and recalculate the order total server-side. Validate quantities and discount eligibility on the server. |
| **Spoofing** | An attacker steals or reuses another user's authentication token/session and performs checkout as that user. | Unauthorized purchases may be made using the victim's account, saved addresses, or associated payment information. This can result in fraud and account compromise. | Use secure session management, short-lived access tokens, secure and `HttpOnly` cookies where appropriate, MFA for sensitive actions, CSRF protection when cookie-based authentication is used, and session invalidation after suspicious activity. |
| **Information Disclosure** | Sensitive checkout or payment-related data is intercepted between the user's browser, the backend, or Stripe, particularly if transport security is missing or misconfigured. | Exposure of personal information, order data, authentication tokens, or payment-related information could lead to fraud, identity theft, and regulatory consequences. | Enforce HTTPS/TLS for all connections, use Stripe-hosted payment components/tokenization so raw card data does not pass through the application server, avoid logging sensitive payment data, and securely manage API secrets. |

### Additional Relevant STRIDE Threats

Other checkout threats may include:

- **Repudiation:** A user disputes having placed an order and the system lacks sufficient audit records.
- **Denial of Service:** Automated requests overload checkout or payment endpoints.
- **Elevation of Privilege:** A normal user exploits an authorization flaw to access administrative checkout or order-management functions.

---

## 2. Trust Boundaries

A trust boundary exists whenever data moves between components with different levels of trust or security control.

### Boundary 1: User Browser ↔ Node.js API

The React frontend runs in the user's browser and must be considered **untrusted** because the user can modify JavaScript, HTTP requests, form values, headers, and API calls.

Data crossing this boundary includes:

- Product IDs
- Cart contents
- Quantities
- Checkout requests
- Authentication tokens
- Shipping information

**Security controls:**

- Server-side validation
- Authentication and authorization
- HTTPS
- Rate limiting
- Input validation
- CSRF protections where applicable

The backend must never rely on the frontend to enforce security-sensitive rules such as prices, discounts, ownership, or permissions.

### Boundary 2: Node.js API ↔ PostgreSQL Database

The application server communicates with the PostgreSQL database, which contains trusted and sensitive application data.

Data crossing this boundary includes:

- SQL queries
- Product information
- User accounts
- Orders
- Addresses
- Application state

A vulnerability in the API, such as SQL injection, could allow untrusted user input to cross this boundary and affect the database.

**Security controls:**

- Parameterized queries/prepared statements
- Least-privilege database accounts
- Database network restrictions
- Input validation
- Encryption for database connections
- Restricted database permissions

### Boundary 3: Node.js API / Browser ↔ Stripe

Stripe is an external third-party service outside the application's direct security control.

Data crossing this boundary may include:

- Payment tokens
- Payment intent identifiers
- Transaction amounts
- Payment status
- Webhook events

Because Stripe is a separate external system, responses and webhook messages must be verified rather than blindly trusted.

**Security controls:**

- HTTPS/TLS
- Stripe tokenization or hosted payment components
- Secure storage of Stripe API keys
- Verification of Stripe webhook signatures
- Server-side verification of payment amount and status
- Idempotency controls for payment operations

### Boundary 4: Unauthenticated ↔ Authenticated Application Functions

The platform exposes some functionality publicly while requiring authentication for checkout and order history.

An important logical trust boundary therefore exists between:

- **Unauthenticated operations:** browsing products and building a cart
- **Authenticated operations:** checkout, payment, and viewing order history

**Security controls:**

- Authentication checks on protected API endpoints
- Object-level authorization
- Session/token validation
- Prevention of insecure direct object reference (IDOR) attacks

For example, knowing an order ID must not allow one authenticated user to retrieve another user's order.

---

## 3. DREAD Rating: SQL Injection in Product Search

Assume that the product search endpoint contains an SQL injection vulnerability because search input is concatenated directly into a PostgreSQL query.

DREAD uses five factors, commonly rated from **1 (low)** to **10 (high)**.

| DREAD Factor | Score | Justification |
|---|---:|---|
| **Damage Potential** | **9/10** | Successful SQL injection could expose product, user, and order information. Depending on database permissions, an attacker might also modify or delete data. The impact could include a major data breach and service disruption. |
| **Reproducibility** | **9/10** | If the vulnerable query behaves consistently, an attacker can repeatedly submit crafted search terms and reproduce the attack without special access. |
| **Exploitability** | **8/10** | Product search is publicly accessible and requires no authentication. SQL injection techniques and automated tools are widely available. Exploitation may require some knowledge of the query or database schema, so the score is slightly below maximum. |
| **Affected Users** | **9/10** | A database compromise could expose information belonging to a large portion of the platform's users rather than only the attacker. The exact impact depends on the database permissions and accessible tables. |
| **Discoverability** | **10/10** | Product search is a public, visible feature. An attacker can easily locate the search input and test it with malformed or specially crafted values. |

### DREAD Calculation

\[
\text{DREAD Score} = \frac{9 + 9 + 8 + 9 + 10}{5} = \frac{45}{5} = 9.0
\]

**Overall DREAD rating: 9.0 / 10 — Critical/High Risk**

### Recommended SQL Injection Mitigations

The primary mitigation is to ensure that user-controlled search input is never concatenated directly into SQL statements.

Recommended controls include:

1. Use **parameterized queries or prepared statements** for all database queries.
2. Use a well-configured ORM or query builder that parameterizes values by default.
3. Run the application using a **least-privilege PostgreSQL account**.
4. Validate input length, type, and expected format.
5. Avoid exposing detailed database error messages to users.
6. Add monitoring and rate limiting to identify automated injection attempts.
7. Include SQL injection tests in security testing and CI/CD processes.

### Example

Unsafe query:

```js
const query = `SELECT * FROM products WHERE name LIKE '%${search}%'`;
```

Safer parameterized query:

```js
const query = 'SELECT * FROM products WHERE name ILIKE $1';
const values = [`%${search}%`];

const result = await db.query(query, values);
```

With parameterization, PostgreSQL treats the search value as data rather than executable SQL, preventing malicious input from changing the structure of the query.

---

## Summary

The checkout flow crosses several security-sensitive boundaries involving the user's browser, the application backend, the PostgreSQL database, and Stripe. Major checkout threats include request tampering, identity/session spoofing, and disclosure of sensitive information.

SQL injection in public product search would be especially serious because the feature is unauthenticated, highly discoverable, and potentially exposes the central application database. Under the assumptions above, it receives a **DREAD score of 9.0/10** and should be treated as a high-priority vulnerability.

