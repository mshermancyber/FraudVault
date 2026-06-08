export {
  type BehaviorVector,
  type NetworkPattern,
  buildBehaviorVector,
  toNumericalVector,
} from './behaviorVector.js';

export {
  FEATURE_WEIGHTS,
  jaccardSimilarity,
  cosineSimilarity,
  fuzzyJaccardSimilarity,
  calculateBehavioralSimilarity,
} from './similarity.js';

export {
  type ClusterResult,
  MalwareFamilyClusterer,
} from './clusterer.js';

export {
  type MalwareFamily,
  type FamilyMembership,
  type FamilyDetails,
  type SimilarSample,
  FamilyManager,
} from './familyManager.js';
