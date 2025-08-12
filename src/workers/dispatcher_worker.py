import asyncio
import logging
from asyncio import Queue

class Dispatcher:
    """
    Pulls refined contexts from a queue and dispatches them to specialized
    AI worker queues based on the context type or content.
    """

    def __init__(self, input_q: Queue, soft_q: Queue, reverse_q: Queue):
        """
        Initializes the dispatcher.

        Args:
            input_q: The queue from which to pull refined contexts.
            soft_q: The queue for soft vulnerability analysis tasks.
            reverse_q: The queue for reverse engineering analysis tasks.
        """
        self.input_q = input_q
        self.soft_q = soft_q
        self.reverse_q = reverse_q
        self.logger = logging.getLogger(self.__class__.__name__)

    async def run(self):
        """
        The main loop for the dispatcher.
        It continuously pulls contexts and routes them.
        """
        self.logger.info("Dispatcher is running.")
        try:
            while True:
                context = await self.input_q.get()
                self.logger.debug(f"Received context: {context}")

                # Simple routing logic: send network requests to both analysis pipelines.
                if context.get('type') == 'network_request':
                    self.logger.info(f"Routing 'network_request' for {context['url']} to AI workers.")
                    # We put the same context into both queues for parallel analysis.
                    await self.soft_q.put(context)
                    await self.reverse_q.put(context)
                else:
                    self.logger.warning(f"No specific route for context type {context.get('type')}. Discarding.")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("Dispatcher is shutting down.")
        except Exception as e:
            self.logger.error(f"An error occurred in Dispatcher: {e}", exc_info=True)