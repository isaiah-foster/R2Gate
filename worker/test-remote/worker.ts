// Placeholder entrypoint: the contract test only uses the CONTRACT R2 binding.
export default {
  fetch(): Response {
    return new Response('r2notary contract test worker\n');
  },
} satisfies ExportedHandler;
