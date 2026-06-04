type RiskEvent = {
  accountActive: boolean;
  manualReview: boolean;
  priority: number;
  region: string;
  items: Array<{ flagged: boolean; reason: string }>;
};

export function routeDecisionTree(event: RiskEvent) {
  let score = 0;
  if (event.accountActive) {
    if (event.region === "EU") {
      for (const item of event.items) {
        if (item.flagged) {
          while (score < 10) {
            if (event.manualReview) {
              score += 3;
            } else if (event.priority > 5) {
              score += 2;
            }
            switch (item.reason) {
              case "refund":
                score += 1;
                break;
              case "abuse":
                score += 4;
                break;
              default:
                score += 1;
                break;
            }
          }
        }
      }
    }
  }
  return score;
}
