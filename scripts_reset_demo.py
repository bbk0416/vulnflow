from __future__ import annotations

from pathlib import Path

from app.core.storage import init_db

root = Path(__file__).resolve().parent
db = root / "data" / "vulnflow.db"
for candidate in [db, Path(str(db) + "-wal"), Path(str(db) + "-shm")]:
    if candidate.exists():
        candidate.unlink()
init_db(db)
print(f"초기화 완료: {db}")
print("서버를 다시 시작하면 검증된 합성 샘플 데이터가 자동 적재됩니다.")
