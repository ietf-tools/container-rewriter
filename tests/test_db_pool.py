"""get_db_pool(): one shared pool, however many milter threads ask first."""
import threading
import time

THREADS = 8


def slow_pool(built):
    class SlowPool:
        check_connection = None

        def __init__(self, **kw):
            built.append(self)
            # time for the other threads to find no pool yet
            time.sleep(0.05)
    return SlowPool


def test_concurrent_first_calls_build_one_pool(rewriter, get_db_pool, monkeypatch):
    built = []
    monkeypatch.setattr(rewriter, "ConnectionPool", slow_pool(built))
    start = threading.Barrier(THREADS)
    pools = []

    def first_message():
        start.wait()
        pools.append(get_db_pool())

    threads = [threading.Thread(target=first_message) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(built) == 1
    assert len(pools) == THREADS
    assert all(p is built[0] for p in pools)


def test_pool_is_reused(rewriter, get_db_pool, monkeypatch):
    built = []
    monkeypatch.setattr(rewriter, "ConnectionPool", slow_pool(built))
    assert get_db_pool() is get_db_pool()
    assert len(built) == 1
