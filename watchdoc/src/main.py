import logging as log

from fastapi import (
    FastAPI,
    BackgroundTasks,
)

from service import WatchDocService
from proto import Applicant
from config import WATCHDOC_PORT

log.basicConfig(
    level="INFO",
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
)

watchdoc = FastAPI()
wds = WatchDocService()


@watchdoc.post("/applicants/")
def post_applicant(applicant: Applicant, background_tasks: BackgroundTasks):
    def closure():
        wds.generate_documents(applicant)

    background_tasks.add_task(closure)
    return "Templates are being generated, wait for the link"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:watchdoc",
        host="0.0.0.0",
        port=WATCHDOC_PORT,
        debug=True,
    )
