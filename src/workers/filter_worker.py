import asyncio
import logging
from asyncio import Queue

class FilterWorker:
    """
    Pulls raw events from a queue, filters them based on predefined criteria
    (e.g., only process network requests), and pushes the refined, valuable
    contexts to the next queue.
    """

    def __init__(self, input_q: Queue, output_q: Queue):
        """
        Initializes the worker.

        Args:
            input_q: The queue from which to pull raw events from the CDPController.
            output_q: The queue to which refined contexts will be sent.
        """
        self.input_q = input_q
        self.output_q = output_q
        self.logger = logging.getLogger(self.__class__.__name__)

    async def run(self):
        """
        The main loop for the worker.
        It continuously pulls events, filters them, and passes them on.
        """
        self.logger.info("Filter Worker is running.")
        try:
            while True:
                # Get a raw event from the input queue
                event = await self.input_q.get()
                self.logger.debug(f"Received event: {event}")

                # We are only interested in network requests.
                if event.get('event_type') == 'request':
                    # Here you can add more sophisticated filtering logic.
                    # For example, ignore requests for images, css, fonts, etc.
                    url = event.get('url', '').lower()
                    if url.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.woff2', '.svg')):
                        self.logger.info(f"Discarding static resource request: {url}")
                        self.input_q.task_done()
                        continue

                    # Transform the event into a more focused context.
                    refined_context = {
                        'type': 'network_request',
                        'url': event['url'],
                        'method': event['method'],
                        'headers': event['headers'],
                        'post_data': event['post_data']
                    }
                    await self.output_q.put(refined_context)
                    self.logger.info(f"Refined and passed on request for: {event['url']}")
                
                # Notify the queue that the task is done
                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("Filter Worker is shutting down.")
        except Exception as e:
            self.logger.error(f"An error occurred in FilterWorker: {e}", exc_info=True)