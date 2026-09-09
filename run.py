import os
from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app()

def seed_initial_users():
    """Seed initial development demonstration accounts with robust passwords."""
    with app.app_context():
        db.create_all()

        # Seed Administrator account
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@securevault.local",
                role="ADMIN",
                is_active=True
            )
            admin.set_password("AdminPass123!")
            db.session.add(admin)
            print("[SecureVault INIT] Default Admin account created: username='admin', password='AdminPass123!'")

        # Seed Standard User account
        alice = User.query.filter_by(username="alice").first()
        if not alice:
            alice = User(
                username="alice",
                email="alice@securevault.local",
                role="USER",
                is_active=True
            )
            alice.set_password("AlicePass123!")
            db.session.add(alice)
            print("[SecureVault INIT] Default User account created: username='alice', password='AlicePass123!'")

        db.session.commit()

if __name__ == "__main__":
    seed_initial_users()
    
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") == "development"

    print("=" * 72)
    print(" 🛡️  SECUREVAULT — ZERO-TRUST ENCRYPTED FILE SHARING PLATFORM")
    print("=" * 72)
    print(" • Encryption:      AES-256-GCM Envelope Encryption (per-file DEK)")
    print(" • Password Hashing: Argon2id (Memory-hard parameters)")
    print(" • File Integrity:  Pre-encryption SHA-256 Re-Verification")
    print(" • Access Control:  RBAC (Admin/User) + Fine-Grained File Permissions")
    print(" • Sharing Engine:  Signed, Expiring, One-Time Burn-After-Reading URLs")
    print(" • Threat Engine:   Rate-limiting, Brute-Force Lockout, Risk Scoring")
    print(f" • Server Online:   http://127.0.0.1:{port}")
    print("=" * 72)

    app.run(host="0.0.0.0", port=port, debug=debug)
